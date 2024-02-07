### CyberSecurity-replacer

Для корректной работы в текущей директории должен лежать файл ```.env```
содержащий имя пользователя и пароль от трекера в виде:
```
REDMINE_USER='username'
REDMINE_PASSWORD='strong-and-complicated-password'
NIST_KEY='nist-api-key'
VULNERS_KEY='vulners-api-key' --ignored for now
TELEGRAM_GROUP_ID='chat-or-group-id'
BOT_TOKEN='bot-token'
GITHUB_TOKEN='token for access to github api'
REPO_PATH='physical path to packages'
REDMINE_URL='tracker url'
KOJI7_URL='local address for stapel7'
KOJI8_URL='local address for stapel8'
```
