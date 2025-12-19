# ------------------------------------------------------------
# Achtung: Speichere diese Datei als credentials.rb
# und trage dann die Daten ein, so werden die Zugangs-
# daten nicht unbeabsichtigt ins Git geschrieben, solange
# der Eintrag src/ruby/credentials.rb in der .gitignore steht.
# ------------------------------------------------------------
DEVELOPMENT = (ENV['DEVELOPMENT'] == '1')
WEBSITE_HOST = ENV['WEBSITE_HOST']
WEB_ROOT = DEVELOPMENT ? 'http://localhost:8025' : "https://#{WEBSITE_HOST}"
QR_BASE_URL = DEVELOPMENT ? 'https://localhost:8025' : "https://#{WEBSITE_HOST}"

PROJECT_NAME = 'Safran'

SEND_MAILS_IN_DEVELOPMENT = false

LOGIN_CODE_SALT = 'ein_schoenes_langes_salt_bitte_hier_einfuegen'

ADMIN_USERS = ['youremailhere@example.com']

SMTP_SERVER = 'smtp_server'
SMTP_USER = 'smtp_user'
SMTP_PASSWORD = 'smtp_password'
SMTP_DOMAIN = 'smtp_domain'
SMTP_FROM = 'Name <E-Mail-Adresse>'

THEME_COLOR = '1e2460'
DARK_THEME_COLOR = '121622'

if defined? Mail
    Mail.defaults do
    delivery_method :smtp, {
        :address => SMTP_SERVER,
        :port => 587,
        :domain => SMTP_DOMAIN,
        :user_name => SMTP_USER,
        :password => SMTP_PASSWORD,
        :authentication => 'login',
        :enable_starttls_auto => true
    } 
    end
end
