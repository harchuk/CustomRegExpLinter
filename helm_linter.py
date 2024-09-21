
import yaml
import re
import sys
import os
import xml.etree.ElementTree as ET

class HelmLinter:
    def __init__(self, chart_dir, config_file):
        self.chart_dir = chart_dir
        self.config_file = config_file
        self.rules = self.load_rules()
        self.violations = []

    def load_rules(self):
        with open(self.config_file, 'r') as file:
            config = yaml.safe_load(file)
        return config['rules']

    def lint_chart(self):
        # Пробегаем по всем файлам в директории чарта
        for root, dirs, files in os.walk(self.chart_dir):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    with open(os.path.join(root, file), 'r') as yaml_file:
                        try:
                            content = yaml.safe_load(yaml_file)
                            self.check_rules(content, os.path.join(root, file))
                        except yaml.YAMLError as exc:
                            print(f"Error parsing {file}: {exc}")
    
    def check_rules(self, content, file_name):
        # Проверяем правила на регулярные выражения
        yaml_string = yaml.dump(content)
        for rule in self.rules:
            pattern = re.compile(rule['regexp'])
            if pattern.search(yaml_string):
                self.violations.append({
                    'id': rule['id'],
                    'description': rule['description'],
                    'severity': rule['severity'],
                    'file': file_name
                })

    def generate_report(self, report_file="report.xml"):
        # Генерируем JUnit отчёт
        testsuite = ET.Element("testsuite", name="helm_linter", tests=str(len(self.rules)))
        for violation in self.violations:
            testcase = ET.SubElement(testsuite, "testcase", classname=violation['file'], name=violation['id'])
            failure = ET.SubElement(testcase, "failure", message=violation['description'], type=violation['severity'])
            failure.text = f"Rule violated in file: {violation['file']}"
        
        tree = ET.ElementTree(testsuite)
        tree.write(report_file, encoding='utf-8', xml_declaration=True)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: helm_linter.py <chart_directory> <config_file>")
        sys.exit(1)
    
    chart_directory = sys.argv[1]
    config_file = sys.argv[2]

    linter = HelmLinter(chart_directory, config_file)
    linter.lint_chart()
    linter.generate_report()
    print(f"Linting complete. Report generated as report.xml.")
