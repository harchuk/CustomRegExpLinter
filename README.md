
# Helm Linter - Кастомный линтер Helm-чартов с поддержкой RegExp

![Helm Linter Logo](/92d34550-6e14-4285-aa71-6d70fc64af32.webp)

Helm Linter — это инструмент для кастомного линтинга Helm-чартов, который проверяет их на соответствие правилам, заданным в виде регулярных выражений (RegExp). Этот линтер легко интегрируется в CI/CD пайплайны Jenkins и GitLab CI, что позволяет автоматически проверять ваши чарты на соответствие лучшим практикам, безопасности и производительности перед развертыванием.

![CI/CD Flow](https://i.ytimg.com/vi/r7hXv8_k9S8/maxresdefault.jpg)

## 📋 Функции

- **Кастомные правила**: Настраиваемые правила линтинга с использованием регулярных выражений через YAML конфигурацию.
- **Интеграция с CI/CD**: Полная поддержка GitLab CI и Jenkins для автоматических проверок.
- **Проверки на безопасность**: Регулярные проверки на настройки безопасности, такие как отсутствие запуска контейнеров под root-пользователем.
- **Генерация отчётов**: Вывод результатов в формате JUnit для анализа в CI системах.

## 🚀 Быстрый старт

### 1. Клонирование проекта

```bash
git clone https://github.com/your-repo/helm-linter.git
cd helm-linter
```

### 2. Установка зависимостей

Проект использует Python и несколько библиотек для работы с YAML и XML. Установите зависимости с помощью `pip`:

```bash
pip install -r requirements.txt
```

### 3. Использование

Для запуска линтера выполните команду, указав директорию с вашим Helm-чартом и файл конфигурации с правилами:

```bash
python helm_linter.py ./your-chart-directory ./linter-rules.yaml
```

После выполнения будет сгенерирован отчёт `report.xml` с результатами линтинга, который можно просмотреть или проанализировать через CI/CD.

![Report Generation](https://www.example.com/report_generation.png)

### Пример конфигурации правил

Пример кастомных правил для линтера в формате YAML:

```yaml
rules:
  - id: "no-root-user"
    description: "Проверяет, что контейнер не запускается под root пользователем"
    severity: "high"
    regexp: "securityContext:\s*runAsUser:\s*0"
  
  - id: "resources-limits"
    description: "Убедитесь, что заданы лимиты ресурсов"
    severity: "medium"
    regexp: "resources:\s*limits:"
    
  - id: "image-tag-not-latest"
    description: "Проверяет, что теги изображений не являются 'latest'"
    severity: "low"
    regexp: "image:\s.*:(?!latest\b)\S+"
```

## 🔄 Интеграция в CI/CD

#### GitLab CI

Используйте следующий `.gitlab-ci.yml` файл для интеграции линтера в GitLab CI:

```yaml
stages:
  - lint

lint_helm_chart:
  stage: lint
  image: python:3.9
  before_script:
    - pip install pyyaml lxml
  script:
    - python helm_linter.py ./your-chart-directory ./linter-rules.yaml
  artifacts:
    reports:
      junit: report.xml
```

#### Jenkins

Пример пайплайна для Jenkins:

```groovy
pipeline {
    agent any

    stages {
        stage('Lint Helm Charts') {
            steps {
                script {
                    sh 'pip install pyyaml lxml'
                    sh 'python helm_linter.py ./your-chart-directory ./linter-rules.yaml'
                }
            }
        }
    }

    post {
        always {
            junit 'report.xml'
        }
    }
}
```

### 5. Использование Docker

Для интеграции с CI/CD можно также использовать Docker. Создайте образ с помощью Dockerfile:

```bash
docker build -t helm-linter:latest .
```

Запуск линтера через Docker:

```bash
docker run -v $(pwd):/app helm-linter:latest ./your-chart-directory ./linter-rules.yaml
```

## 🛠 Разработка

Если вы хотите участвовать в развитии проекта, делайте форк репозитория, создавайте ветки и предлагайте изменения через PR.

## 📄 Лицензия

Этот проект лицензирован под MIT License — смотрите файл [LICENSE](LICENSE) для подробностей.
