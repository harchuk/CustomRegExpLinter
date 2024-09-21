import yaml
import re
import sys
import os
import json
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

class FileLinter:
    def __init__(self, directory, config_file, severity_filter=None, output_format="xml", verbose=False, dry_run=False):
        self.directory = directory
        self.config_file = config_file
        self.rules = self.load_rules()
        self.violations = []
        self.severity_filter = severity_filter
        self.output_format = output_format
        self.verbose = verbose
        self.dry_run = dry_run

        # Уровень логирования
        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

    def load_rules(self):
        if self.verbose:
            logging.debug("Loading rules from config file.")
        with open(self.config_file, 'r') as file:
            config = yaml.safe_load(file)
        return config['rules']
    
    def lint_chart(self):
        files_to_process = []
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                files_to_process.append(os.path.join(root, file))
        
        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(self.lint_file, file): file for file in files_to_process}
            for future in as_completed(futures):
                file_name = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    logging.error(f"Error processing file {file_name}: {exc}")
    
    def lint_file(self, file_path):
        if self.verbose:
            logging.debug(f"Linting file: {file_path}")
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                self.check_rules(content, file_path)
        except Exception as e:
            logging.error(f"Error reading or parsing {file_path}: {e}")
    
    def check_rules(self, content, file_name):
        file_size_kb = os.path.getsize(file_name) / 1024
        num_lines = content.count('\n') + 1

        for rule in self.rules:
            # Игнорирование файлов по маске
            if 'ignore_file_regexp' in rule and re.match(rule['ignore_file_regexp'], file_name):
                if self.verbose:
                    logging.debug(f"File {file_name} ignored by rule {rule['id']}")
                continue
            
            # Проверка по имени файла
            if 'file_name_regexp' in rule and not re.match(rule['file_name_regexp'], file_name):
                if self.verbose:
                    logging.debug(f"File {file_name} does not match file_name_regexp for rule {rule['id']}")
                continue

            # Фильтрация по уровню серьезности
            if self.severity_filter and rule['severity'] != self.severity_filter:
                continue

            # Проверка по содержимому файла (регулярное выражение)
            if 'regexp' in rule:
                pattern = re.compile(rule['regexp'])
                if pattern.search(content):
                    self.log_violation(rule, file_name)

            # Проверка по количеству строк
            if 'max_lines' in rule and num_lines > rule['max_lines']:
                self.log_violation(rule, file_name, f"File exceeds {rule['max_lines']} lines.")

            # Проверка по размеру файла
            if 'max_size_kb' in rule and file_size_kb > rule['max_size_kb']:
                self.log_violation(rule, file_name, f"File exceeds {rule['max_size_kb']} KB.")

    def log_violation(self, rule, file_name, additional_info=None):
        violation = {
            'id': rule['id'],
            'description': rule['description'],
            'severity': rule['severity'],
            'file': file_name
        }
        if additional_info:
            violation['description'] += f" ({additional_info})"
        self.violations.append(violation)
        if self.verbose:
            logging.debug(f"Violation found: {violation}")

    def generate_report(self, report_file="report.xml"):
        if self.dry_run:
            logging.info("Dry run enabled, no report will be generated.")
            return

        if self.output_format == "xml":
            self.generate_junit_report(report_file)
        elif self.output_format == "json":
            self.generate_json_report(report_file)
        elif self.output_format == "html":
            self.generate_html_report(report_file)
    
    def generate_junit_report(self, report_file):
        testsuite = ET.Element("testsuite", name="file_linter", tests=str(len(self.violations)))
        for violation in self.violations:
            testcase = ET.SubElement(testsuite, "testcase", classname=violation['file'], name=violation['id'])
            failure = ET.SubElement(testcase, "failure", message=violation['description'], type=violation['severity'])
            failure.text = f"Rule violated in file: {violation['file']}"
        tree = ET.ElementTree(testsuite)
        tree.write(report_file, encoding='utf-8', xml_declaration=True)
        logging.info(f"JUnit report generated: {report_file}")

    def generate_json_report(self, report_file):
        with open(report_file, 'w') as f:
            json.dump({"violations": self.violations}, f, indent=2)
        logging.info(f"JSON report generated: {report_file}")

    def generate_html_report(self, report_file):
        html_content = "<html><body><h1>Linting Report</h1><ul>"
        for violation in self.violations:
            html_content += f"<li><strong>{violation['file']}</strong>: {violation['description']} (severity: {violation['severity']})</li>"
        html_content += "</ul></body></html>"
        with open(report_file, 'w') as f:
            f.write(html_content)
        logging.info(f"HTML report generated: {report_file}")

def send_to_webhook(self, webhook_url, payload):
        try:
            response = requests.post(webhook_url, json=payload)
            if response.status_code == 200:
                logging.info("Report successfully sent to webhook.")
            else:
                logging.error(f"Failed to send report to webhook. Status code: {response.status_code}")
        except Exception as e:
            logging.error(f"Error sending report to webhook: {e}")

    # Вызов этой функции после генерации отчета
    def post_linting_results(self, webhook_url):
        payload = {
            "summary": {
                "total_files_checked": len(self.violations),
                "total_violations": len(self.violations),
                "violations_by_severity": {
                    "high": len([v for v in self.violations if v['severity'] == 'high']),
                    "medium": len([v for v in self.violations if v['severity'] == 'medium']),
                    "low": len([v for v in self.violations if v['severity'] == 'low'])
                }
            },
            "violations": self.violations
        }
        self.send_to_webhook(webhook_url, payload)

if __name__ == "__main__":
     # Парсинг аргументов командной строки
    parser = argparse.ArgumentParser(description="File Linter for DevOps")
    parser.add_argument("directory", help="Directory with files to lint")
    parser.add_argument("config_file", help="YAML config file with linting rules")
    parser.add_argument("--severity-filter", help="Filter by severity level (e.g., high, medium, low)", default=None)
    parser.add_argument("--output-format", help="Format of the report (xml, json, html)", default="xml")
    parser.add_argument("--verbose", help="Enable verbose output", action="store_true")
    parser.add_argument("--fail-on-severity", help="Exit with error code if any violations have this severity level", default=None)
    parser.add_argument("--dry-run", help="Perform a dry run without generating a report", action="store_true")
    parser.add_argument("--webhook-url", help="Webhook URL for sending reports to external systems", default=None)   
    args = parser.parse_args()

    linter = FileLinter(
        directory=args.directory,
        config_file=args.config_file,
        severity_filter=args.severity_filter,
        output_format=args.output_format,
        verbose=args.verbose,
        dry_run=args.dry_run
    )

    # Выполнение линтинга
    linter.lint_chart()

    if args.fail_on_severity:
        violations = [v for v in linter.violations if v['severity'] == args.fail_on_severity]
        if violations:
            logging.error(f"Violations with severity {args.fail_on_severity} found. Exiting with error.")
            sys.exit(1)

    # Генерация отчета
    linter.generate_report()

    # Если указан webhook URL, отправляем результат
    if args.webhook_url:
        linter.post_linting_results(args.webhook_url)

    print(f"Linting complete. Report generated in {args.output_format} format.")
