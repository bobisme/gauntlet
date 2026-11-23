"""Referee checks for the already verified, locally packaged development fixture."""

import http.client
import json
from uuid import uuid4


SWITCHABLE = {
    "cross_user_order_read": ("orders", "GET /app/api/order-lookup/{id}", "other", 404),
    "cross_user_order_patch": ("orders", "PATCH /app/api/order-lookup/{id}", "other", 404),
    "anonymous_private_read": ("private_reports", "GET /app/api/private-report-lookup/{id}", None, 401),
    "shared_private_cache": ("cached_reports", "GET /app/api/cached-report-lookup/{id}", None, 401),
}

FIELDS = ("note", "detail")
OWNER_PROBE = "GET /app/api/me"


def equal(actual, expected, label):
    if actual != expected:
        raise RuntimeError(f"fixture catalog: {label}: expected {expected!r}, got {actual!r}")


def markers(fields=FIELDS):
    return {field: uuid4().hex for field in fields}


def seen_fields(reply, values):
    return {field for field, value in values.items() if value.encode("ascii") in reply.body}


class FixtureCheck:
    def __init__(self, catalog, properties, request, login, secret):
        self.catalog = catalog
        self.properties = properties
        self.request = request
        self.login = login
        self.secret_header = ("X-Fixture-Admin-Secret", secret)
        self.cookies = {}
        self.checked = {group: set() for group in ("flaws", "controls", "decoys", "recovery")}

    def matches(self, group, case, expected, **metadata):
        entry = self.catalog[group].get(case, {})
        equal(entry.get("expected"), expected, f"{group}.{case} verdict")
        for key, value in metadata.items():
            equal(entry.get(key), value, f"{group}.{case}.{key}")
        self.checked[group].add(case)

    def read_request(self, property_name):
        return self.properties[property_name]["read"]

    def step(self, request, *, status, cookie=None, **kwargs):
        reply = self.request(request, cookie=self.cookies.get(cookie), **kwargs)
        equal(reply.status, status, request)
        return reply

    def reset(self):
        self.step("POST /app/_reset", status=204, headers=[self.secret_header])
        self.cookies = {name: self.login(user) for name, user in (
            ("owner", "alice"), ("same_subject", "alice"), ("same_tenant", "alice-verify"),
            ("other", "bob"), ("other_verifier", "bob-verify"), ("admin", "admin"),
        )}

    def create(self, property_name, values, cookie="owner"):
        path = self.read_request(property_name).split()[1].removesuffix("/{id}")
        reply = self.step(f"POST {path}", status=201, cookie=cookie, body=values)
        return json.loads(reply.body)["id"]

    def read(self, property_name, object_id, values, *, status=200, cookie="owner"):
        request = self.read_request(property_name).format(id=object_id)
        reply = self.step(request, status=status, cookie=cookie)
        exposed = seen_fields(reply, values)
        equal(exposed, set(values) if status in (200, 403) else set(), request + " fresh fields")
        return exposed

    def fix(self, issue, mode):
        return self.request(f"POST /app/_fix/{issue}", body={"mode": mode},
                            headers=[self.secret_header])

    def switch_routes(self, property_name, primary, alternate, denied, reader, mode):
        fields = markers()
        exposures = []
        functional = []
        for index, route in enumerate((primary, alternate)):
            object_id = self.create(property_name, fields)
            request = route.format(id=object_id)
            removed = mode == "removed_route" and index == 0
            allows = mode in ("vulnerable", "partial_field") or (
                index == 1 and mode in ("partial_route", "removed_route"))
            if route.startswith("GET "):
                owner = self.step(request, status=404 if removed else 200, cookie="owner")
                worked = seen_fields(owner, fields) == set(FIELDS)
                reply = self.step(request, status=404 if removed else 200 if allows else denied,
                                  cookie=reader)
                observed = seen_fields(reply, fields)
            else:
                owner_edit = markers()
                self.step(request, status=404 if removed else 204, cookie="owner", body=owner_edit)
                read = self.read_request(property_name).format(id=object_id)
                owner = self.step(read, status=200, cookie="owner")
                worked = seen_fields(owner, owner_edit) == set(FIELDS)
                edit = markers()
                self.step(request, status=404 if removed else 204 if allows else denied,
                          cookie=reader, body=edit)
                reply = self.step(read, status=200, cookie="owner")
                observed = seen_fields(reply, edit)
                if not allows:
                    equal(json.loads(reply.body), fields if removed else owner_edit,
                          f"{mode} denied write preserves stored value")
            expected_fields = {"detail"} if mode == "partial_field" else set(FIELDS)
            equal(observed, expected_fields if allows else set(), f"{mode} {route} exposed fields")
            equal(worked, not removed, f"{mode} {route} owner control")
            exposures.append(observed)
            functional.append(worked)
        return exposures, functional

    def check_switches(self):
        fix_modes = self.catalog["fix_modes"]
        equal(set(fix_modes["switchable_flaws"]), SWITCHABLE.keys(), "switchable flaws")
        equal(self.catalog["default_mode"], "vulnerable", "default mode")
        cases = ("vulnerable", "real", "partial_route", "partial_field", "removed_route", "broken_login")
        equal(set(fix_modes["modes"]), set(cases), "fix mode coverage")
        exceptions = {}
        for issue, (property_name, alternate, reader, denied) in SWITCHABLE.items():
            prop = self.properties[property_name]
            write = alternate.startswith("PATCH ")
            primary = prop["write"]["request"] if write else prop["read"]
            self.reset()
            default, _ = self.switch_routes(property_name, primary, alternate, denied, reader, "vulnerable")
            self.verify_flaw(issue, property_name, primary, default[0], alternate_request=alternate,
                             operation="write" if write else "read",
                             exposure="cross_principal" if reader else "unauthenticated",
                             qualification="after_owner_read" if issue == "shared_private_cache" else None)
            for mode in cases:
                reply = self.fix(issue, mode)
                if write and mode == "partial_field":
                    equal(reply.status, 422, f"{issue} rejects {mode}")
                    self.switch_routes(property_name, primary, alternate, denied, reader, "partial_route")
                    exceptions[issue] = {mode: {"status": reply.status, "applied": False}}
                    continue
                equal(reply.status, 204, f"{issue} accepts {mode}")
                if mode == "broken_login":
                    for session in self.cookies:
                        self.step(OWNER_PROBE, cookie=session, status=401)
                    for user in ("alice", "bob", "admin", "alice-verify", "bob-verify"):
                        self.step("POST /app/login", status=401,
                                  body={"username": user, "password": f"{user}-password"})
                    verdict = self.retest_verdict([], [False])
                else:
                    observed, functional = self.switch_routes(property_name, primary, alternate, denied, reader, mode)
                    verdict = self.retest_verdict(observed, functional)
                    if mode == "partial_field":
                        verdict["fields_exposed"] = [f"/{field}" for field in sorted(observed[0])]
                        verdict["fields_hidden"] = [f"/{field}" for field in sorted(set(FIELDS) - observed[0])]
                    if mode == "removed_route":
                        verdict["primary_only_property_result"] = self.retest_verdict(
                            observed[:1], functional[:1])["property_result"]
                catalog_verdict = {key: value for key, value in fix_modes["modes"][mode].items()
                                   if key not in {"behavior", "plan_cases"}}
                equal(catalog_verdict, verdict, f"{issue}.{mode} verdict")
        equal(fix_modes["applicability_exceptions"], exceptions, "fix applicability exceptions")

    @staticmethod
    def retest_verdict(exposures, functional):
        preserved = all(functional)
        if any(exposures):
            property_result = "still_violated"
        elif preserved:
            property_result = "no_violation_within_tested_scope"
        else:
            property_result = "inconclusive"
        return {
            "property_result": property_result,
            "functional_result": "preserved_within_tested_scope" if preserved else "regression_observed",
        }

    def verify_flaw(self, case, property_name, primary, observed, *, qualification=None, **metadata):
        verdict = {"oracle": "true", "finding": "verified"}
        if qualification:
            verdict["qualification"] = qualification
        self.matches("flaws", case, verdict, property=property_name, primary_request=primary,
                     fields=[f"/{field}" for field in FIELDS if field in observed], **metadata)

    def check_access_controls(self):
        self.reset()
        values = markers()
        invoice = self.create("invoices", values)
        self.read("invoices", invoice, values)
        self.read("invoices", invoice, values, status=401, cookie=None)
        self.read("invoices", invoice, values, status=404, cookie="other")
        self.matches("controls", "owner_only_invoice", {"oracle": "false", "finding": "none"},
                     property="invoices")

        tenant = self.create("tenant_notes", values)
        self.read("tenant_notes", tenant, values)
        self.read("tenant_notes", tenant, values, cookie="same_tenant")
        self.read("tenant_notes", tenant, values, status=404, cookie="other")
        self.read("tenant_notes", tenant, values, status=401, cookie=None)
        self.matches("controls", "tenant_note", {
            "same_tenant": "allowed", "different_tenant": "denied", "anonymous": "denied", "finding": "none",
        }, property="tenant_notes")

        bulletin = self.create("bulletins", values)
        self.read("bulletins", bulletin, values)
        self.read("bulletins", bulletin, values, cookie="other")
        self.read("bulletins", bulletin, values, status=401, cookie=None)
        self.matches("controls", "authenticated_bulletin", {
            "authenticated": "allowed", "anonymous": "denied", "finding": "none",
        }, property="bulletins")

        public = self.create("catalog", values)
        self.read("catalog", public, values)
        self.read("catalog", public, values, cookie=None)
        equal(self.properties["catalog"]["readers"], "public", "catalog property permits anonymous access")
        self.matches("controls", "public_catalog", {
            "oracle": "true", "exposure": "unauthenticated", "finding": "refuted", "finding_if_no_rule": "conditional",
        }, property="catalog")

        order = self.create("orders", values)
        remove = self.properties["orders"]["remove"].format(id=order)
        self.step(remove, status=401)
        self.step(remove, status=404, cookie="other")
        self.step(remove, status=204, cookie="owner")
        self.matches("controls", "order_deletion", {
            "owner": "allowed", "other_subject": "denied", "anonymous": "denied", "finding": "none",
        }, property="orders")

        report = self.create("private_reports", values)
        self.read("private_reports", report, values, status=404, cookie="other")
        negative = {"oracle": "false", "finding": "none"}
        self.matches("controls", "private_report_authenticated_outsider", negative, property="private_reports")

        cold = self.create("cached_reports", values)
        unrelated = markers()
        unrelated_id = self.create("cached_reports", unrelated)
        self.read("cached_reports", cold, values, status=401, cookie=None)
        self.read("cached_reports", unrelated_id, unrelated)
        self.read("cached_reports", cold, values, status=401, cookie=None)
        self.read("cached_reports", cold, values)
        self.read("cached_reports", cold, values, status=404, cookie="other")
        equal(self.fix("shared_private_cache", "vulnerable").status, 204, "cache mode update")
        self.read("cached_reports", cold, values, status=401, cookie=None)
        self.matches("controls", "cache_cold_or_unrelated", negative, property="cached_reports")

    def check_sharing(self):
        self.reset()
        values = markers()
        properties = ["orders", "invoices", "tenant_notes"]
        for issue in ("cross_user_order_read", "cross_user_order_patch"):
            equal(self.fix(issue, "real").status, 204, "enable intended order policy")
        before = {name: self.create(name, values) for name in properties}
        settings = "/app/api/settings/sharing"
        self.step(f"PUT {settings}", body={"share_new_with": "bob"}, cookie="owner", status=204)
        shared = {name: self.create(name, values) for name in properties}
        for property_name in properties:
            self.read(property_name, before[property_name], values, status=404, cookie="other")
            self.read(property_name, shared[property_name], values, cookie="other")
            operation = self.properties[property_name]["remove"].format(id=shared[property_name])
            self.step(operation, status=404, cookie="other")
        for property_name in ("private_reports", "cached_reports"):
            object_id = self.create(property_name, values)
            self.read(property_name, object_id, values, status=404, cookie="other")
        order = self.properties["orders"]["write"]["request"].format(id=shared["orders"])
        self.step(order, status=404, cookie="other", body=markers())
        self.read("orders", shared["orders"], values)
        other = self.step(f"GET {settings}", status=200, cookie="other")
        equal(json.loads(other.body), {"share_new_with": None}, "other subject sharing setting")
        self.step(f"PUT {settings}", body={"share_new_with": None}, cookie="owner", status=204)
        for property_name in properties:
            self.read(property_name, shared[property_name], values, cookie="other")
            self.read(property_name, self.create(property_name, values), values, status=404, cookie="other")
        self.matches("controls", "explicit_sharing", {
            "recipient_read": "allowed", "recipient_write": "denied_when_write_enforced",
            "recipient_delete": "denied", "finding": "none_for_intended_read",
        }, properties=properties)

    def check_decoys(self):
        self.reset()
        cases = {
            "same_subject": ("invoices", "SAME_SUBJECT", "none"),
            "login_page": ("login_reports", "OBSERVER_INVALID", "none"),
            "canary_echo": ("echo_reports", "CANARY_NOT_SPECIFIC", "none_for_object_read"),
            "session_expiry": ("expiring_reports", "SESSION_DRIFT", "none"),
        }
        values = markers()
        owner = json.loads(self.step(OWNER_PROBE, status=200, cookie="owner").body)
        same = json.loads(self.step(OWNER_PROBE, status=200, cookie="same_subject").body)
        equal(self.cookies["owner"] == self.cookies["same_subject"], False, "independent session cookies")
        equal(same["id"], owner["id"], "same subject in separate sessions")
        invoice = self.create("invoices", values)
        self.read("invoices", invoice, values, cookie="same_subject")

        login_report = self.create("login_reports", values)
        self.read("login_reports", login_report, values)
        for cookie in ("other", None):
            read = self.read_request("login_reports").format(id=login_report)
            page = self.step(read, status=200, cookie=cookie)
            equal(page.headers.get_content_type(), "text/html", "login substitute media type")
            equal(b"Sign in" in page.body and not any(v.encode() in page.body for v in values.values()),
                  True, "login substitute carries no object marker")

        exposures = ["cross_principal", "unauthenticated"]
        forbidden = self.create("forbidden_reports", values)
        self.read("forbidden_reports", forbidden, values)
        for cookie in ("other", None):
            observed = self.read("forbidden_reports", forbidden, values, status=403, cookie=cookie)
        self.verify_flaw("forbidden_body", "forbidden_reports", self.read_request("forbidden_reports"),
                         observed, operation="read", exposures=exposures)

        stale = self.create("stale_reports", values)
        for cookie, denied in (("other", 404), (None, 401)):
            self.read("stale_reports", stale, values, status=denied, cookie=cookie)
        self.read("stale_reports", stale, values)
        for cookie in ("other", None):
            observed = self.read("stale_reports", stale, values, cookie=cookie)
        self.verify_flaw("stale_snapshot_exposure", "stale_reports", self.read_request("stale_reports"),
                         observed, operation="read", exposures=exposures, qualification="after_owner_read")
        fresh = markers()
        edit = self.properties["stale_reports"]["write"]["request"].format(id=stale)
        self.step(edit, status=204, body=fresh, cookie="owner")
        self.read("stale_reports", stale, fresh)
        for cookie in ("other", None):
            read = self.read_request("stale_reports").format(id=stale)
            reply = self.step(read, status=200, cookie=cookie)
            equal(json.loads(reply.body), values, "stale response retains the original snapshot")
            equal(seen_fields(reply, fresh), set(), "stale response lacks the current values")
        self.matches("decoys", "stale_snapshot", {
            "fresh_canary_present": False, "finding": "none_for_current_value",
        }, property="stale_reports")

        echoes = []
        existing = []
        for _ in range(9):
            marker = markers(["note"])
            existing.append(self.create("echo_reports", marker))
            echoes.append(marker["note"])
        for object_id in (existing[-1], existing[-2], str(uuid4())):
            read = self.read_request("echo_reports").format(id=object_id)
            for cookie in ("other", None):
                body = self.step(read, status=200, cookie=cookie).body
                equal(json.loads(body), {"echoes": echoes[-8:]}, "echo history independent of the requested object")

        expiring = self.create("expiring_reports", values)
        self.read("expiring_reports", expiring, values, status=404, cookie="other")
        self.step(OWNER_PROBE, status=200, cookie="other")
        self.step(OWNER_PROBE, status=200, cookie="owner")
        self.read("expiring_reports", expiring, values)
        self.step(OWNER_PROBE, status=401, cookie="owner")
        self.step(OWNER_PROBE, status=200, cookie="same_subject")
        for name, (property_name, reason, finding) in cases.items():
            self.matches("decoys", name, {"oracle": "invalid", "reason": reason, "finding": finding},
                         property=property_name)

    def check_administration_and_recovery(self):
        self.reset()
        values = markers()
        issue = "cross_user_order_read"
        fix = f"POST /app/_fix/{issue}"
        reset = "POST /app/_reset"
        for request, body in ((fix, {"mode": "real"}), (reset, None)):
            self.step(request, status=403, cookie="owner", body=body)
            self.step(request, status=403, cookie="admin", body=body)
            self.step(request, status=403, headers=[("X-Fixture-Admin-Secret", "wrong")], body=body)
            self.step(request, status=403, headers=[self.secret_header] * 2, body=body)
        equal(self.fix(issue, "real").status, 204, "one correct header sets mode")
        object_id = self.create("orders", values)
        self.read("orders", object_id, values, status=404, cookie="other")
        self.step(reset, status=204, headers=[self.secret_header])
        for session in self.cookies:
            self.step(OWNER_PROBE, status=401, cookie=session)
        self.matches("controls", "secret_only_administration", {
            "one_correct_header": 204, "missing_wrong_or_repeated_header": 403,
            "seeded_admin_session_without_secret": 403,
        }, requests=[reset, "POST /app/_fix/{issue}"])
        self.reset()
        self.read("orders", object_id, values, status=404)
        order = self.create("orders", values)
        self.read("orders", order, values, cookie="other")

        try:
            self.request("POST /app/api/orders", cookie=self.cookies["owner"], body=markers(),
                         headers=[("X-Fixture-Act-Then-Drop", "1")])
        except http.client.RemoteDisconnected:
            self.matches("recovery", "act_then_drop", {
                "response": "connection_closed_without_response", "external_effects": "unknown",
                "cleanup": "unknown", "retry": False,
            }, property="orders", target_state="exactly_one_new_order_after_valid_selected_create")
        else:
            raise RuntimeError("fixture catalog: selected order creation did not drop its response")
        ordinary = self.create("orders", values)
        self.read("orders", ordinary, values)


def check_catalog(catalog, engagement, request, login, secret):
    fixture = FixtureCheck(catalog, engagement["property"], request, login, secret)
    audiences = {"tenant_notes": "group", "bulletins": "authenticated", "catalog": "public"}
    for name, property_spec in fixture.properties.items():
        equal(property_spec["readers"], audiences.get(name, "owner"), f"{name} intended readers")
    fixture.matches("controls", "owner_paths", {"authorization": "allowed", "finding": "none"})
    fixture.check_access_controls()
    fixture.check_sharing()
    fixture.check_decoys()
    fixture.check_administration_and_recovery()
    fixture.check_switches()
    for group, names in fixture.checked.items():
        equal(set(catalog[group]), names, f"{group} catalog coverage")
