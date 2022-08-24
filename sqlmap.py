from bbot.modules.base import BaseModule


class sqlmap(BaseModule):

    watched_events = ["URL"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "aggressive", "web", "slow", "brute-force", "deadly"]
    meta = {"description": "Unleash SQLMAP against unsuspecting web applications"}

    options = {"smart_mode": True, "level": "1", "risk": "1", "crawl": "2"}
    options_desc = {
        "smart_mode": "Perform thorough tests only if positive heuristic(s) STRONGLY RECOMMENDED",
        "level": "Level of tests to perform (1-5, default 1)",
        "risk": "Risk of tests to perform (1-3, default 1)",
        "crawl": "Sets the max crawl depth for looking for additional links. 0 will disable the feature.",
        "tamper": "Use given script(s) for tampering injection data (comma separated)",
    }

    in_scope_only = True

    deps_ansible = [
        {
            "name": "Get SQLMAP repo",
            "git": {"repo": "https://github.com/sqlmapproject/sqlmap.git", "dest": "{BBOT_TOOLS}/sqlmap"},
        }
    ]

    def setup(self):
        sqlmap_warned = False
        for m in self.scan.modules.values():

            if "URL" in m.produced_events and sqlmap_warned == False:
                if str(m) != "httpx":
                    sqlmap_warned = True
                    self.hugewarning(
                        "Warning! Running SQLMAP module with non-httpx URL event producers could produce undesirable effects! Proceed with caution!"
                    )

        self.crawl = self.config.get("crawl", "2")
        self.level = self.config.get("level", "1")
        self.risk = self.config.get("risk", "1")
        self.smart_mode = self.config.get("smart_mode", True)
        self.tamper = self.config.get("tamper", "")

        self.hugeinfo(self.smart_mode)
        self.hugeinfo(self.crawl)
        self.hugeinfo(self.level)

        return True

    def handle_event(self, event):

        command = [
            "python",
            f"{self.scan.helpers.tools_dir}/sqlmap/sqlmap.py",
            f"{event.data}",
            "--batch",
            "--forms",
            "--flush-session",
            "--user-agent",
            f"{self.scan.useragent}",
            "--level",
            f"{self.level}",
            "--risk",
            f"{self.risk}",
            "--crawl",
            f"{self.crawl}",
        ]

        if self.smart_mode:
            command.append("--smart")

        if self.tamper:
            command.append(f'--tamper="{self.tamper}"')

        # This is really ugly, yes!
        # Why can't there by a json output mode?

        vuln_dict = {}
        expect_vuln = False
        for f in self.helpers.run_live(command):

            if "(XSS) test shows that" in f and "might be vulnerable to cross" in f:
                parameter = f.split("'")[1]

                self.emit_event(
                    {
                        "host": str(event.host),
                        "url": event.data,
                        "description": f"Possible XSS Injection parameter: [{parameter}]",
                    },
                    "FINDING",
                    event,
                )

            if "appears to be" in f and "injectable" in f:

                parameter = f.split("'")[1]
                technique = f.split("'")[3]

                self.emit_event(
                    {
                        "host": str(event.host),
                        "url": event.data,
                        "description": f"Possible SQL Injection parameter: [{parameter}] technique: [{technique}]",
                    },
                    "FINDING",
                    event,
                )

            if expect_vuln == False and "sqlmap identified the following injection point(s)" in f:
                expect_vuln = True

            if expect_vuln == True:

                if "do you want to exploit" in f:
                    vuln_dict = {}
                    expect_vuln = False

                elif ":" in f:
                    parsed_line = f.strip().split(":")
                    vuln_dict[parsed_line[0].strip().replace(":", "")] = parsed_line[1].strip()

            if "Parameter" in vuln_dict and "Type" in vuln_dict and "Title" in vuln_dict and "Payload" in vuln_dict:

                self.emit_event(
                    {
                        "severity": "HIGH",
                        "host": str(event.host),
                        "url": str(event.data),
                        "description": f"SQL Injection Type: [{vuln_dict['Type']}] Title: [{vuln_dict['Title']}] Payload: [{vuln_dict['Payload']}]",
                    },
                    "VULNERABILITY",
                    event,
                )

                del vuln_dict["Type"]
                del vuln_dict["Title"]
                del vuln_dict["Payload"]
