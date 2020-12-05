from email.utils import parseaddr
import argparse
import subprocess
import os
import pwd
import grp
import re
import stat
from typing import List, Union

def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

dehydrated_hook = """
#!/usr/bin/env bash

deploy_challenge() {
    local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

    # This hook is called once for every domain that needs to be
    # validated, including any alternative names you may have listed.
    #
    # Parameters:
    # - DOMAIN
    #   The domain name (CN or subject alternative name) being
    #   validated.
    # - TOKEN_FILENAME
    #   The name of the file containing the token to be served for HTTP
    #   validation. Should be served by your web server as
    #   /.well-known/acme-challenge/${TOKEN_FILENAME}.
    # - TOKEN_VALUE
    #   The token value that needs to be served for validation. For DNS
    #   validation, this is what you want to put in the _acme-challenge
    #   TXT record. For HTTP validation it is the value that is expected
    #   be found in the $TOKEN_FILENAME file.

    # Simple example: Use nsupdate with local named
    # printf 'server 127.0.0.1\\nupdate add _acme-challenge.%s 300 IN TXT "%s"\\nsend\\n' "${DOMAIN}" "${TOKEN_VALUE}" | nsupdate -k /var/run/named/session.key
}

clean_challenge() {
    local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

    # This hook is called after attempting to validate each domain,
    # whether or not validation was successful. Here you can delete
    # files or DNS records that are no longer needed.
    #
    # The parameters are the same as for deploy_challenge.

    # Simple example: Use nsupdate with local named
    # printf 'server 127.0.0.1\\nupdate delete _acme-challenge.%s TXT "%s"\\nsend\\n' "${DOMAIN}" "${TOKEN_VALUE}" | nsupdate -k /var/run/named/session.key
}

sync_cert() {
    local KEYFILE="${1}" CERTFILE="${2}" FULLCHAINFILE="${3}" CHAINFILE="${4}" REQUESTFILE="${5}"

    # This hook is called after the certificates have been created but before
    # they are symlinked. This allows you to sync the files to disk to prevent
    # creating a symlink to empty files on unexpected system crashes.
    #
    # This hook is not intended to be used for further processing of certificate
    # files, see deploy_cert for that.
    #
    # Parameters:
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
    # - REQUESTFILE
    #   The path of the file containing the certificate signing request.

    # Simple example: sync the files before symlinking them
    # sync "${KEYFILE}" "${CERTFILE}" "${FULLCHAINFILE}" "${CHAINFILE}" "${REQUESTFILE}"
}

deploy_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}" TIMESTAMP="${6}"

    # This hook is called once for each certificate that has been
    # produced. Here you might, for instance, copy your new certificates
    # to service-specific locations and reload the service.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
    # - TIMESTAMP
    #   Timestamp when the specified certificate was created.

    # Simple example: Copy file to nginx config
    # cp "${KEYFILE}" "${FULLCHAINFILE}" /etc/nginx/ssl/; chown -R nginx: /etc/nginx/ssl
    systemctl reload nginx
}

deploy_ocsp() {
    local DOMAIN="${1}" OCSPFILE="${2}" TIMESTAMP="${3}"

    # This hook is called once for each updated ocsp stapling file that has
    # been produced. Here you might, for instance, copy your new ocsp stapling
    # files to service-specific locations and reload the service.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - OCSPFILE
    #   The path of the ocsp stapling file
    # - TIMESTAMP
    #   Timestamp when the specified ocsp stapling file was created.

    # Simple example: Copy file to nginx config
    # cp "${OCSPFILE}" /etc/nginx/ssl/; chown -R nginx: /etc/nginx/ssl
    # systemctl reload nginx
}


unchanged_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}"

    # This hook is called once for each certificate that is still
    # valid and therefore wasn't reissued.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
}

invalid_challenge() {
    local DOMAIN="${1}" RESPONSE="${2}"

    # This hook is called if the challenge response has failed, so domain
    # owners can be aware and act accordingly.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - RESPONSE
    #   The response that the verification server returned

    # Simple example: Send mail to root
    # printf "Subject: Validation of ${DOMAIN} failed!\\n\\nOh noez!" | sendmail root
}

request_failure() {
    local STATUSCODE="${1}" REASON="${2}" REQTYPE="${3}" HEADERS="${4}"

    # This hook is called when an HTTP request fails (e.g., when the ACME
    # server is busy, returns an error, etc). It will be called upon any
    # response code that does not start with '2'. Useful to alert admins
    # about problems with requests.
    #
    # Parameters:
    # - STATUSCODE
    #   The HTML status code that originated the error.
    # - REASON
    #   The specified reason for the error.
    # - REQTYPE
    #   The kind of request that was made (GET, POST...)
    # - HEADERS
    #   HTTP headers returned by the CA

    # Simple example: Send mail to root
    # printf "Subject: HTTP request failed failed!\\n\\nA http request failed with status ${STATUSCODE}!" | sendmail root
}

generate_csr() {
    local DOMAIN="${1}" CERTDIR="${2}" ALTNAMES="${3}"

    # This hook is called before any certificate signing operation takes place.
    # It can be used to generate or fetch a certificate signing request with external
    # tools.
    # The output should be just the certificate signing request formatted as PEM.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain as specified in domains.txt. This does not need to
    #   match with the domains in the CSR, it's basically just the directory name.
    # - CERTDIR
    #   Certificate output directory for this particular certificate. Can be used
    #   for storing additional files.
    # - ALTNAMES
    #   All domain names for the current certificate as specified in domains.txt.
    #   Again, this doesn't need to match with the CSR, it's just there for convenience.

    # Simple example: Look for pre-generated CSRs
    # if [ -e "${CERTDIR}/pre-generated.csr" ]; then
    #   cat "${CERTDIR}/pre-generated.csr"
    # fi
}

startup_hook() {
  # This hook is called before the cron command to do some initial tasks
  # (e.g. starting a webserver).

  :
}

exit_hook() {
  local ERROR="${1:-}"

  # This hook is called at the end of the cron command and can be used to
  # do some final (cleanup or other) tasks.
  #
  # Parameters:
  # - ERROR
  #   Contains error message if dehydrated exits with error
}

HANDLER="$1"; shift
if [[ "${HANDLER}" =~ ^(deploy_challenge|clean_challenge|sync_cert|deploy_cert|deploy_ocsp|unchanged_cert|invalid_challenge|request_failure|generate_csr|startup_hook|exit_hook)$ ]]; then
  "$HANDLER" "$@"
fi
"""


class Apt:

    def install(self, packages: List[str], needed: bool=True, **kwargs) -> None:
        s = self._apt("install", packages)
        if s["code"] != 0:
            raise Exception("Failed to install: {0}".format(s["stderr"]))

    def refresh(self, **kwargs) -> None:
        s = self._apt("update")
        if s["code"] != 0:
            raise Exception("Failed to refresh: {0}".format(s["stderr"]))

    def upgrade(self, packages: List[str]=None, **kwargs) -> None:
        s = self._apt("upgrade", packages)
        if s["code"] != 0:
            raise Exception("Failed to upgrade: {0}".format(s["stderr"]))

    def remove(self, packages: List[str], purge: bool=False, **kwargs) -> None:
        eflgs = []
        if purge:
            eflgs.append('--purge')

        s = self._apt("remove", packages, eflgs=eflgs)
        if s["code"] != 0:
            raise Exception("Failed to upgrade: {0}".format(s["stderr"]))

    def get_updatable(self, **kwargs) -> List[dict]:
        s = self._apt("list", eflgs=['--upgradable'], all_yes=False)
        if s["code"] != 0:
            raise Exception("Failed to get updatable: {0}".format(s["stderr"]))

        compiled = re.compile(r'^(\S+)\/\S+\s+(\S+)\s+\S+\s+\[upgradable from: (\S+)]$')

        data = []
        rows = [x for x in s["stdout"].split('\n') if x]
        for row in rows:
            found = compiled.search(row)
            if found:
                data.append({
                    'name': found.group(1),
                    'from_version': found.group(2),
                    'to_version': found.group(3),
                })
        return data

    def get_all(self, **kwargs) -> List[dict]:
        s = self._apt("list", eflgs=['--all-versions'], all_yes=False)
        if s["code"] != 0:
            raise Exception("Failed to get_all: {0}".format(s["stderr"]))

        compiled = re.compile(r'^(\S+)\/\S+\s+(\S+)\s+\S+$')

        data = []
        rows = [x for x in s["stdout"].split('\n') if x]
        for row in rows:
            found = compiled.search(row)
            if found:
                data.append({
                    'name': found.group(1),
                    'version': found.group(2)
                })
        return data

    def get_installed(self, **kwargs) -> List[dict]:
        s = self._apt("list", eflgs=['--installed'], all_yes=False)
        if s["code"] != 0:
            raise Exception("Failed to get_installed: {0}".format(s["stderr"]))

        compiled = re.compile(r'^(\S+)\/\S+\s+(\S+)\s+\S+\s+\[installed(:?.+|)]$')

        data = []
        rows = [x for x in s["stdout"].split('\n') if x]
        for row in rows:
            found = compiled.search(row)
            if found:
                data.append({
                    'name': found.group(1),
                    'version': found.group(2)
                })
        return data

    def get_info(self, package: str, **kwargs) -> dict:
        s = self._apt("show", package, all_yes=False)
        if s["code"] != 0:
            raise Exception("Failed to get_info: {0}".format(s["stderr"]))

        version_re = re.compile(r'^Version:\s+(\S+)$')
        name_re = re.compile(r'^Package:\s+(\S+)$')
        installed_size_re = re.compile(r'^Installed-Size:\s+(\S+)$')
        description_re = re.compile(r'^Description:(\s+(?:.|\n )+)$')

        rows = [x for x in s["stdout"].split('\n') if x]
        name = None
        version = None
        description = None
        installed_size = None

        for row in rows:
            found_name = name_re.search(row)
            if found_name:
                name = found_name.group(1)

            found_version = version_re.search(row)
            if found_version:
                version = found_version.group(1)

            found_installed_size = installed_size_re.search(row)
            if found_installed_size:
                installed_size = found_installed_size.group(1)

            found_description = description_re.search(row)
            if found_description:
                description = found_description.group(1)

        return {'name': name, 'version': version, 'description': description, 'installed_size': installed_size}

    def is_installed(self, package: str, **kwargs) -> bool:
        # Return True if the specified package is installed
        return self._dpkg('-s', package)['code'] == 0

    def _apt(self, flags: str, pkgs: Union[List[str], str, None]=None, eflgs: Union[List[str], None]=None, all_yes: bool = True) -> dict:
        # Subprocess wrapper, get all data

        if not pkgs:
            pkgs = []

        if not eflgs:
            eflgs = []

        cmd = ['apt']

        if all_yes:
            cmd.append('-yq')

        cmd.append(flags)

        if pkgs:
            cmd += pkgs if type(pkgs) == list else [pkgs]

        if eflgs and any(eflgs):
            eflgs = [x for x in eflgs if x]
            cmd += eflgs
        p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        data = p.communicate()
        data = {"code": p.returncode, "stdout": data[0].decode(),
                "stderr": data[1].rstrip(b'\n').decode()}
        return data

    def _dpkg(self, flags: str, pkgs: Union[List[str], str, None]=None, eflgs: Union[List[str], None]=None) -> dict:
        # Subprocess wrapper, get all data

        if not pkgs:
            pkgs = []

        if not eflgs:
            eflgs = []

        if not pkgs:
            cmd = ["dpkg", flags]
        elif type(pkgs) == list:
            cmd = ["dpkg", flags]
            cmd += pkgs
        else:
            cmd = ["dpkg", flags, pkgs]
        if eflgs and any(eflgs):
            eflgs = [x for x in eflgs if x]
            cmd += eflgs
        p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        data = p.communicate()
        data = {"code": p.returncode, "stdout": data[0].decode(),
                "stderr": data[1].rstrip(b'\n').decode()}
        return data


class Npm:
    def install(self, packages: List[str]):
        cmd = ['npm', 'install'] + packages + ['-g']
        p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        data = p.communicate()
        if p.returncode != 0:
            raise Exception('Command {} failed with code {}: {}'.format(cmd, p.returncode, data[1].decode()))
        return data[0].decode()


class Prep:
    system_depedencies = ['sudo', 'nodejs', 'dehydrated', 'nginx', 'npm']
    npm_depedencies = ['pm2']
    def __init__(self, domains: List[str], nodejs_app_path: str, run_as_user: str, email: str, nodejs_app_port: int):
        if len(domains) == 0:
            raise Exception('No domains provided!')

        if not os.path.isfile(nodejs_app_path):
            raise Exception('NodeJS app {} was not found!'.format(nodejs_app_path))

        self.domains = domains
        self.nodejs_app_path = nodejs_app_path
        self.run_as_user = run_as_user
        self.nodejs_app_port = nodejs_app_port
        self.email = email
        self.apt = Apt()
        self.npm = Npm()

        # Run
        print('== Checking system packages...')
        self.check_system_packages()
        print('== Checking NPM packages...')
        self.check_npm_packages()
        print('== Setup NodeJS app in PM2...')
        self.setup_pm2_app()
        print('== Setup http NGINX...')
        self.setup_http_nginx()
        print('== Setup dehydrated and requesting LetsEncrypt certificate...')
        self.setup_dehydrated()
        print('== Setup https NGINX...')
        self.setup_https_nginx()

    def system_call(self, command: list, expected_return_code: int=0) -> str:
        p = subprocess.Popen(command, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        data = p.communicate()
        if p.returncode != expected_return_code:
            raise Exception('Command {} failed with return code {}: {}'.format(command, p.returncode, data[1].decode()))
        return data[0].decode()

    def check_system_packages(self):
        # Refresh repository info
        print('=== Refreshing APT repositories...')
        self.apt.refresh()
        # If there are any packages to upgrade, do it
        if len(self.apt.get_updatable()) > 0:
            print('=== Upgrading APT packages...')
            self.apt.upgrade()
        else:
            print('=== No APT packages to upgrade...')

        # Check what packages are installed and what we need to install
        print('=== Checking if there are any packages that needs to be installed...')
        installed_names = [installed_package['name'] for installed_package in self.apt.get_installed()]
        to_install = list(set(self.system_depedencies) - set(installed_names))
        if len(to_install):
            # Install missing packages
            print('=== Installing missing packages {}...'.format(to_install))
            self.apt.install(to_install)
        else:
            print('=== Nothing to install...')


    def check_npm_packages(self):
        self.npm.install(self.npm_depedencies)

    def setup_pm2_app(self):
        self.system_call(['sudo', '-u', self.run_as_user, 'pm2', 'start', self.nodejs_app_path, '-f'])
        self.system_call(['pm2', 'startup', 'systemd', '-u', self.run_as_user, '--hp', os.path.expanduser('~{}'.format(self.run_as_user))])
        self.system_call(['sudo', '-u', self.run_as_user, 'pm2', 'save'])

    def setup_http_nginx(self):
        # Disable default config
        if os.path.isfile('/etc/nginx/sites-enabled/default'):
            os.remove('/etc/nginx/sites-enabled/default')
        # Create initial http setup for each domain
        is_first = True
        for domain in self.domains:
            with open('/etc/nginx/sites-available/{}'.format(domain), 'w') as wf:
                content = [
                    'server {',
                    '    listen 80{};'.format(' default_server' if is_first else ''),
                    '    listen [::]:80{};'.format(' default_server' if is_first else ''),
                    '    server_name {};'.format(domain),
                    '',
                    '    # Lets encrypt validation dir',
                    '    location ^~ /.well-known/acme-challenge {',
                    '        alias /var/www/dehydrated;',
                    '    }',
                    '',
                    '    location / {',
                    '        proxy_pass http://127.0.0.1:{};'.format(self.nodejs_app_port),
                    '        proxy_http_version 1.1;',
                    '        proxy_set_header Upgrade $http_upgrade;',
                    '        proxy_set_header Connection \'upgrade\';',
                    '        proxy_set_header Host $host;',
                    '        proxy_cache_bypass $http_upgrade;',
                    '    }',
                    '}'
                ]
                wf.write('\n'.join(content))
            # Enable new config
            if not os.path.islink('/etc/nginx/sites-enabled/{}'.format(domain)):
                os.symlink('/etc/nginx/sites-available/{}'.format(domain), '/etc/nginx/sites-enabled/{}'.format(domain))
            is_first = False
        self.system_call(['systemctl', 'restart', 'nginx'])
        self.system_call(['systemctl', 'enable', 'nginx'])

    def setup_dehydrated(self):
        hook_path = '/etc/dehydrated/hook.sh'
        # Create domains.txt
        with open('/etc/dehydrated/domains.txt', 'w') as wf:
            wf.write(' '.join(self.domains))

        # Create hook.sh
        with open(hook_path, 'w') as wf:
            wf.write(dehydrated_hook)

        # Make hook.sh runnable
        st = os.stat(hook_path)
        os.chmod(hook_path, st.st_mode | stat.S_IEXEC)

        # Create my.cnf
        with open('/etc/dehydrated/conf.d/my.sh', 'w') as wf:
            content = [
                'CONTACT_EMAIL="{}"'.format(self.email),
                'HOOK="{}"'.format(hook_path),
                'WELLKNOWN="/var/www/dehydrated"'
            ]
            wf.write('\n'.join(content))

        # Create wellknown dir
        if not os.path.isdir('/var/www/dehydrated'):
            os.mkdir('/var/www/dehydrated')
        uid = pwd.getpwnam("www-data").pw_uid
        gid = grp.getgrnam("www-data").gr_gid
        os.chown('/var/www/dehydrated', uid, gid)

        # Setup CRON
        with open('/etc/cron.d/dehydrated', 'w') as wf:
            wf.write('0 0 * * 0 root /usr/bin/dehydrated --cron >> /root/ssl_check.log')
        self.system_call(['dehydrated', '--register', '--accept-terms'])
        self.system_call(['dehydrated', '--cron'])


    def setup_https_nginx(self):
        # Overwrite nginx config with SSL config
        is_first = True
        for domain in self.domains:
            with open('/etc/nginx/sites-available/{}'.format(domain), 'w') as wf:
                content = [
                    'server {',
                    '    listen       80{};'.format(' default_server' if is_first else ''),
                    '    listen       [::]:80{};'.format(' default_server' if is_first else ''),
                    '    server_name  {};'.format(domain),
                    '',
                    '    return       301 https://{}\$request_uri;'.format(domain),
                    '}',
                    '',
                    'server {',
                    '    listen 443 http2{};'.format(' default_server' if is_first else ''),
                    '    listen [::]:443 http2{};'.format(' default_server' if is_first else ''),
                    '    server_name {};'.format(domain),
                    '',
                    '    ssl on;',
                    '    ssl_certificate /var/lib/dehydrated/certs/{}/fullchain.pem;'.format(self.domains[0]),
                    '    ssl_certificate_key /var/lib/dehydrated/certs/{}/privkey.pem;'.format(self.domains[0]),
                    '',
                    '    ssl_session_timeout 5m;',
                    '',
                    '',
                    '    # Lets encrypt validation',
                    '    location ^~ /.well-known/acme-challenge {',
                    '        alias /var/www/dehydrated;',
                    '    }',
                    '',
                    '    location / {',
                    '        proxy_pass http://127.0.0.1:{};'.format(self.nodejs_app_port),
                    '        proxy_http_version 1.1;',
                    '        proxy_set_header Upgrade $http_upgrade;',
                    '        proxy_set_header Connection \'upgrade\';',
                    '        proxy_set_header Host $host;',
                    '        proxy_cache_bypass $http_upgrade;',
                    '    }',
                    '}',
                ]
                wf.write('\n'.join(content))
                is_first = False

        self.system_call(['systemctl', 'restart', 'nginx'])


if __name__ == '__main__':
    if os.geteuid() != 0:
        print('You need to be root to run this script!')
        exit()

    # Parameters
    # domains: domains separated by coma
    # nodejs_app_path: Path to nodejs main.js
    # run_as_user: User to run nodejs app under
    # email: Email of user to register letsencrypt under

    parser = argparse.ArgumentParser(description='Setup nodejs server app with NGINX SSL proxy.')

    parser.add_argument('email', metavar='E', type=str,
                    help='Email for letsencrypt registration')

    parser.add_argument('nodejs_app_path', metavar='N', type=str,
                    help='Absolute path to nodejs app to run')

    parser.add_argument('run_as_user', metavar='U', type=str,
                    help='Under what user the nodejs app should be run')

    parser.add_argument('nodejs_app_port', metavar='P', type=int,
                    help='What port does nodejs app use')

    parser.add_argument('domains', metavar='D', type=str, nargs='+',
                    help='Doman to handle, can be used multiple times')

    args = parser.parse_args()

    # Check if valid email is provided
    if '@' not in parseaddr(args.email)[1]:
        raise Exception('Email {} is not valid email'.format(args.email))

    for domain in args.domains:
        if not is_valid_hostname(domain):
            raise Exception('Domain {} is not valid domain'.format(domain))

    if not os.path.isfile(args.nodejs_app_path):
        raise Exception('Path to nodejs app {} is not valid'.format(args.nodejs_app_path))

    try:
        pwd.getpwnam(args.run_as_user)
    except KeyError:
        raise Exception('User {} does not exist.'.format(args.run_as_user))

    try:
       prep = Prep(domains=args.domains, nodejs_app_path=args.nodejs_app_path, run_as_user=args.run_as_user, email=args.email, nodejs_app_port=args.nodejs_app_port)
    except Exception as e:
       print('!==== {} ====!'.format(e))


