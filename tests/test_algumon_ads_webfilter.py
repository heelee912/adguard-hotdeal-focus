from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FILTER_PATH = ROOT / "algumon-ads-webfilter.txt"
POLICY_PATH = ROOT / "ALGUMON_ADS_NETWORK_POLICY.md"
CLI_PATH = ROOT / "scripts" / "adguard_windows_cli.ps1"
SUBSCRIPTION_URL = (
    "https://raw.githubusercontent.com/heelee912/adguard-hotdeal-focus/main/"
    "algumon-ads-webfilter.txt"
)
ALLOWED_HOSTS = {
    "safeframe.googlesyndication.com",
    "pagead2.googlesyndication.com",
    "tpc.googlesyndication.com",
    "securepubads.g.doubleclick.net",
    "pubads.g.doubleclick.net",
    "googleads.g.doubleclick.net",
    "googletagservices.com",
    "googleadservices.com",
    "beacons.gvt2.com",
}


class AlgumonAdsWebFilterTests(unittest.TestCase):
    def test_subscription_is_an_exact_algumon_scoped_exception_set(self) -> None:
        rules = [
            line.strip()
            for line in FILTER_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("!")
        ]
        self.assertEqual(
            set(rules),
            {
                f"@@||{host}^$domain=algumon.com"
                for host in ALLOWED_HOSTS
            },
        )
        self.assertEqual(len(rules), len(ALLOWED_HOSTS))
        self.assertTrue(
            all(
                rule.startswith("@@||")
                and rule.endswith("^$domain=algumon.com")
                for rule in rules
            )
        )

    def test_policy_requires_the_initiator_aware_web_layer(self) -> None:
        policy = POLICY_PATH.read_text(encoding="utf-8")
        self.assertIn(SUBSCRIPTION_URL, policy)
        self.assertIn("$domain=algumon.com", policy)
        self.assertIn("fail-closed", policy)
        self.assertIn("NextDNS alone cannot", policy)
        self.assertNotIn("@@||algumon.com^$document", FILTER_PATH.read_text(encoding="utf-8"))

    def test_stale_policy_is_refreshed_before_exact_verification(self) -> None:
        cli = CLI_PATH.read_text(encoding="utf-8")
        install = cli[
            cli.index("function Install-AlgumonAdDeliveryPolicy"):
            cli.index("function Get-EnabledAlgumonDocumentWideExceptions")
        ]
        self.assertIn("$requiresRefresh", install)
        self.assertIn("CheckForFilterSubscriptionsUpdate", install)
        self.assertIn("Assert-AlgumonAdDeliveryPolicyInstalled", install)
        self.assertLess(
            install.index("CheckForFilterSubscriptionsUpdate"),
            install.index("Assert-AlgumonAdDeliveryPolicyInstalled"),
        )


if __name__ == "__main__":
    unittest.main()
