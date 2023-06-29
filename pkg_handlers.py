import os
import re
import json
import koji
from enum import Enum
from random import choice
import urllib.parse as parse
from itertools import zip_longest

USERS_LIST = f"{os.path.expanduser('.')}/users.json"
TAG_LIST = [
    "os72-updates",
    "os73-updates",
    "os73-kernel6",
]
KOJI_URL = "http://10.81.1.26/kojihub"


class PatchResult(Enum):
    FAILED = 1
    ALREADY_APPLIED = 2
    NO_FILE = 3
    SUCCESS = 4


class IsXIssue(Enum):
    NO = 1
    MAYBE = 2
    YES = 3


def compare_versions(ver_a: str, ver_b: str) -> bool:
    """
    Сравниватель версий по старшинству. Нормально обрабатывает буквенные версии
    """
    def replace_chars_with_ord(ver_str: str) -> str:
        result_str = ""
        for char in ver_str:
            result_str += str(ord(char)) if char.isalpha() else char
        return result_str

    ver_a_list = list(map(int, replace_chars_with_ord(ver_a).split('.')))
    ver_b_list = list(map(int, replace_chars_with_ord(ver_b).split('.')))

    for a, b in zip_longest(ver_a_list, ver_b_list, fillvalue=0):
        if a > b:
            return True
        elif b > a:
            return False
    return True


def ver_max(ver_list: list) -> str:
    max_atm = "0"
    for ver in ver_list:
        if compare_versions(ver, max_atm):
            max_atm = ver
    return max_atm


def split_and_strip(string: str) -> list:
    return re.sub(r'[^\w\s]', ' ', string).split()


class PkgHandler:

    def get_latest_rpm_data(self, package_name, tag_name, deep=True) -> dict:
        """
        На входе получает имя пакета, на выходе отдает dict с информацией по нему
        :param tag_name: Тег, в котором проверяем
        :param package_name: Имя пакета
        :param deep: Флаг, какую логику использовать для поиска последнего пакета.
        В случае False будет брать последней по дате, что может быть не слишком удачным выбором
        :return: dict с инфой по пакету в случае успеха, None в противном случае
        """
        if deep:
            package_list_raw = self.session.listTagged(tag_name['id'], package=package_name)
            if not package_list_raw:
                # на случай если не нашли в теге, ищем через наследование по простому
                package_list = self.session.getLatestRPMS(tag_name['id'], arch='src', package=package_name)[1]
                return package_list[0] if package_list else {}

            # выделим старшую эпоху
            epoch_list = [i['epoch'] for i in package_list_raw if i['epoch']]
            latest_epoch = max(epoch_list) if epoch_list else None
            latest_rpms = list(
                filter(lambda x: x['epoch'] == latest_epoch, package_list_raw)) \
                if latest_epoch else package_list_raw
            # старшую версию
            latest_version = ver_max([i['version'] for i in latest_rpms])
            latest_rpms = list(filter(lambda x: x['version'] == latest_version, latest_rpms))
            # и старший релиз
            latest_release = ver_max([i['release'].split('.')[0] for i in latest_rpms])
            package_list = list(filter(lambda x: x['release'].split('.')[0] == latest_release, latest_rpms))
        else:
            package_list = self.session.getLatestRPMS(tag_name['id'], arch='src', package=package_name)[1]

        return package_list[0] if package_list else {}

    def __init__(self):

        with open(USERS_LIST) as f:
            self.users_dict = json.loads(f.read())

        self.session = koji.ClientSession(KOJI_URL)
        self.tags = [self.session.getTag(tag) for tag in TAG_LIST]

        self.pkgs_data = {
            'kernel': {
                'check_func': self.is_kernel_issue,
                'cve_counter': 0,
                'stapel_name': 'kernel-lt',
                'nvr_list': [self.get_latest_rpm_data("kernel-lt", tag).get('version', "") for tag in self.tags],
                'check_patch': True,
                'assigned_to': int(self.users_dict['artem.chernyshev']),
                'watchers': [int(self.users_dict['artem.chernyshev'])],
            },
            'Vim': {
                'check_func': self.is_vim_issue,
                'cve_counter': 0,
                'stapel_name': 'vim',
                'nvr_list': [self.get_latest_rpm_data("vim", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['artem.chernyshev']),
                'watchers': [int(self.users_dict['artem.chernyshev'])],
            },
            'nextcloud': {
                'check_func': self.is_nextcloud_generic_issue,
                'cve_counter': 0,
                'stapel_name': 'nextcloud',
                'nvr_list': [self.get_latest_rpm_data("nextcloud", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'nextcloud-server': {
                'check_func': self.is_nextcloud_server_issue,
                'cve_counter': 0,
                'stapel_name': 'nextcloud',
                'nvr_list': [self.get_latest_rpm_data("nextcloud", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'nextcloud-mail': {
                'check_func': self.is_nextcloud_mail_issue,
                'cve_counter': 0,
                'stapel_name': 'nextcloud-app-mail',
                'nvr_list': [self.get_latest_rpm_data("nextcloud-app-mail", tag).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'nextcloud-calendar': {
                'check_func': self.is_nextcloud_calendar_issue,
                'cve_counter': 0,
                'stapel_name': 'nextcloud-app-calendar',
                'nvr_list': [self.get_latest_rpm_data("nextcloud-app-calendar", tag).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'nextcloud-contacts': {
                'check_func': self.is_nextcloud_contacts_issue,
                'cve_counter': 0,
                'stapel_name': 'nextcloud-app-contacts',
                'nvr_list': [self.get_latest_rpm_data("nextcloud-app-contacts", tag).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'gpac': {
                'check_func': self.is_gpac_issue,
                'cve_counter': 0,
                'stapel_name': 'gpac',
                'nvr_list': [self.get_latest_rpm_data("gpac", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'redis': {
                'check_func': self.is_redis_issue,
                'cve_counter': 0,
                'stapel_name': 'redis',
                'nvr_list': [self.get_latest_rpm_data("redis", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'systemd': {
                'check_func': self.is_systemd_issue,
                'cve_counter': 0,
                'stapel_name': 'systemd',
                'nvr_list': [self.get_latest_rpm_data("systemd", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'django': {
                'check_func': self.is_django_issue,
                'cve_counter': 0,
                'stapel_name': 'python-django',
                'nvr_list': [self.get_latest_rpm_data("python-django", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vitaly.peshcherov']),
                                       int(self.users_dict['ilia.polyvyanyy'])]),
                'watchers': None,
            },
            'moodle': {
                'check_func': self.is_moodle_issue,
                'cve_counter': 0,
                'stapel_name': 'moodle',
                'nvr_list': [self.get_latest_rpm_data("moodle", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vladislav.mitin']),
                                       int(self.users_dict['ilia.polyvyanyy'])]),
                'watchers': None,
            },
            'Firefox': {
                'check_func': self.is_firefox_issue,
                'cve_counter': 0,
                'stapel_name': 'firefox',
                'nvr_list': [self.get_latest_rpm_data("firefox", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': [int(self.users_dict['oleg.shaposhnikov'])],
            },
            'Thunderbird': {
                'check_func': self.is_thunderbird_issue,
                'cve_counter': 0,
                'stapel_name': 'thunderbird',
                'nvr_list': [self.get_latest_rpm_data("thunderbird", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': [int(self.users_dict['oleg.shaposhnikov'])],
            },
            'cURL': {
                'check_func': self.is_curl_issue,
                'cve_counter': 0,
                'stapel_name': 'curl',
                'nvr_list': [self.get_latest_rpm_data("curl", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'glpi': {
                'check_func': self.is_glpi_issue,
                'cve_counter': 0,
                'stapel_name': 'glpi',
                'nvr_list': [self.get_latest_rpm_data("glpi", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': None,
            },
            'libtiff': {
                'check_func': self.is_libtiff_issue,
                'cve_counter': 0,
                'stapel_name': 'libtiff',
                'nvr_list': [self.get_latest_rpm_data("libtiff", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'grafana': {
                'check_func': self.is_grafana_issue,
                'cve_counter': 0,
                'stapel_name': 'grafana',
                'nvr_list': [self.get_latest_rpm_data("grafana", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'ImageMagick': {
                'check_func': self.is_imagemagick_issue,
                'cve_counter': 0,
                'stapel_name': 'ImageMagick',
                'nvr_list': [self.get_latest_rpm_data("ImageMagick", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'qemu': {
                'check_func': self.is_qemu_issue,
                'cve_counter': 0,
                'stapel_name': 'qemu',
                'nvr_list': [self.get_latest_rpm_data("qemu", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'Wireshark': {
                'check_func': self.is_wireshark_issue,
                'cve_counter': 0,
                'stapel_name': 'wireshark',
                'nvr_list': [self.get_latest_rpm_data("wireshark", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'libvirt': {
                'check_func': self.is_libvirt_issue,
                'cve_counter': 0,
                'stapel_name': 'libvirt',
                'nvr_list': [self.get_latest_rpm_data("libvirt", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vitaly.peshcherov']),
                                       int(self.users_dict['vladislav.mitin']),
                                       int(self.users_dict['dmitry.safonov'])]),
                'watchers': None,
            },
            'libraw': {
                'check_func': self.is_libraw_issue,
                'cve_counter': 0,
                'stapel_name': 'LibRaw',
                'nvr_list': [self.get_latest_rpm_data("LibRaw", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'samba': {
                'check_func': self.is_samba_issue,
                'cve_counter': 0,
                'stapel_name': 'samba',
                'nvr_list': [self.get_latest_rpm_data("samba", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['dmitry.safonov']),
                'watchers': None,
            },
            'openSSL': {
                'check_func': self.is_openssl_issue,
                'cve_counter': 0,
                'stapel_name': 'openssl',
                'nvr_list': [self.get_latest_rpm_data("openssl", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vladislav.mitin']),
                                       int(self.users_dict['ilia.polyvyanyy'])]),
                'watchers': None,
            },
            'yasm': {
                'check_func': self.is_yasm_issue,
                'cve_counter': 0,
                'stapel_name': 'yasm',
                'nvr_list': [self.get_latest_rpm_data("yasm", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'Emacs': {
                'check_func': self.is_emacs_issue,
                'cve_counter': 0,
                'stapel_name': 'emacs',
                'nvr_list': [self.get_latest_rpm_data("emacs", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'libreswan': {
                'check_func': self.is_libreswan_issue,
                'cve_counter': 0,
                'stapel_name': 'libreswan',
                'nvr_list': [self.get_latest_rpm_data("libreswan", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'libreoffice': {
                'check_func': self.is_libreoffice_issue,
                'cve_counter': 0,
                'stapel_name': 'libreoffice',
                'nvr_list': [self.get_latest_rpm_data("libreoffice", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'sudo': {
                'check_func': self.is_sudo_issue,
                'cve_counter': 0,
                'stapel_name': 'sudo',
                'nvr_list': [self.get_latest_rpm_data("sudo", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'podofo': {
                'check_func': self.is_podofo_issue,
                'cve_counter': 0,
                'stapel_name': 'podofo',
                'nvr_list': [self.get_latest_rpm_data("podofo", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'opensearch': {
                'check_func': self.is_opensearch_issue,
                'cve_counter': 0,
                'stapel_name': 'opensearch',
                'nvr_list': [self.get_latest_rpm_data("opensearch", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'libheif': {
                'check_func': self.is_libheif_issue,
                'cve_counter': 0,
                'stapel_name': 'libheif',
                'nvr_list': [self.get_latest_rpm_data("libheif", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'flask': {
                'check_func': self.is_flask_issue,
                'cve_counter': 0,
                'stapel_name': 'python-flask',
                'nvr_list': [self.get_latest_rpm_data("python-flask", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'cups-filters': {
                'check_func': self.is_cups_filters_issue,
                'cve_counter': 0,
                'stapel_name': 'cups-filters',
                'nvr_list': [self.get_latest_rpm_data("cups-filters", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'Lua': {
                'check_func': self.is_lua_issue,
                'cve_counter': 0,
                'stapel_name': 'lua',
                'nvr_list': [self.get_latest_rpm_data("lua", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'nginx': {
                'check_func': self.is_nginx_issue,
                'cve_counter': 0,
                'stapel_name': 'nginx',
                'nvr_list': [self.get_latest_rpm_data("nginx", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vitaly.peshcherov']),
                                       int(self.users_dict['vladislav.mitin'])]),
                'watchers': None,
            },
            'tcpdump': {
                'check_func': self.is_tcpdump_issue,
                'cve_counter': 0,
                'stapel_name': 'tcpdump',
                'nvr_list': [self.get_latest_rpm_data("tcpdump", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vitaly.peshcherov']),
                                       int(self.users_dict['alexey.rodionov'])]),
                'watchers': None,
            },
            'tmux': {
                'check_func': self.is_tmux_issue,
                'cve_counter': 0,
                'stapel_name': 'tmux',
                'nvr_list': [self.get_latest_rpm_data("tmux", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['artem.chernyshev']),
                'watchers': None,
            },
            'flatpak': {
                'check_func': self.is_flatpak_issue,
                'cve_counter': 0,
                'stapel_name': 'flatpak',
                'nvr_list': [self.get_latest_rpm_data("flatpak", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': None,
            },
            'runc': {
                'check_func': self.is_runc_issue,
                'cve_counter': 0,
                'stapel_name': 'runc',
                'nvr_list': [self.get_latest_rpm_data("runc", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'Moby': {
                'check_func': self.is_moby_issue,
                'cve_counter': 0,
                'stapel_name': 'moby-engine',
                'nvr_list': [self.get_latest_rpm_data("moby-engine", tag).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'libssh': {
                'check_func': self.is_libssh_issue,
                'cve_counter': 0,
                'stapel_name': 'libssh',
                'nvr_list': [self.get_latest_rpm_data("libssh", tag).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'c-ares': {
                'check_func': self.is_c_ares_issue,
                'cve_counter': 0,
                'stapel_name': 'c-ares',
                'nvr_list': [self.get_latest_rpm_data("c-ares", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vitaly.peshcherov']),
                                       int(self.users_dict['vladislav.mitin']),
                                       int(self.users_dict['ilia.polyvyanyy']),
                                       int(self.users_dict['alexey.rodionov'])]),
                'watchers': None,
            },
            'Avahi': {
                'check_func': self.is_avahi_issue,
                'cve_counter': 0,
                'stapel_name': 'avahi',
                'nvr_list': [self.get_latest_rpm_data("avahi", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vitaly.peshcherov']),
                                       int(self.users_dict['alexey.rodionov'])]),
                'watchers': None,
            },
            'openSC': {
                'check_func': self.is_opensc_issue,
                'cve_counter': 0,
                'stapel_name': 'opensc',
                'nvr_list': [self.get_latest_rpm_data("opensc", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vitaly.peshcherov']),
                'watchers': None,
            },
            'gRPC': {
                'check_func': self.is_grpc_issue,
                'cve_counter': 0,
                'stapel_name': 'grpc',
                'nvr_list': [self.get_latest_rpm_data("grpc", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['ilia.polyvyanyy']),
                                       int(self.users_dict['dmitry.safonov'])]),
                'watchers': None,
            },
            'libexpat': {
                'check_func': self.is_libexpat_issue,
                'cve_counter': 0,
                'stapel_name': 'expat',
                'nvr_list': [self.get_latest_rpm_data("expat", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['ilia.polyvyanyy']),
                                       int(self.users_dict['vladislav.mitin'])]),
                'watchers': None,
            },
            'libjxl': {
                'check_func': self.is_libjxl_issue,
                'cve_counter': 0,
                'stapel_name': 'jpegxl',
                'nvr_list': [self.get_latest_rpm_data("jpegxl", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'openldap': {
                'check_func': self.is_openldap_issue,
                'cve_counter': 0,
                'stapel_name': 'openldap',
                'nvr_list': [self.get_latest_rpm_data("openldap", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'Netty': {
                'check_func': self.is_netty_issue,
                'cve_counter': 0,
                'stapel_name': 'netty',
                'nvr_list': [self.get_latest_rpm_data("netty", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'Nettle': {
                'check_func': self.is_nettle_issue,
                'cve_counter': 0,
                'stapel_name': 'nettle',
                'nvr_list': [self.get_latest_rpm_data("nettle", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'pyPdf': {
                'check_func': self.is_pypdf_issue,
                'cve_counter': 0,
                'stapel_name': 'pyPdf',
                'nvr_list': [self.get_latest_rpm_data("pyPdf", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
        }

    # Нижеследующие функции проверяют, относится ли уязвимость к соответствующему пакету
    @staticmethod
    def is_kernel_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к ядреной
        """
        check_urls = [
            'lore.kernel.org',
            'git.kernel.org',
            'lkml.org',
            'bugzilla.redhat.com',
            'bugzilla.suse.com',
            'cdn.kernel.org',
            'lkml.kernel.org',
            'kernel.dance',
            'lists.debian.org',
            'www.debian.org',
            'www.spinics.net',
            'patchwork.kernel.org',
        ]

        if ('linux kernel' not in desc) or ('android linux kernel' in desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if (netloc == 'github.com' and path_first == 'torvalds') or (netloc in check_urls):
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_vim_issue(desc, links) -> IsXIssue:
        if 'vim' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'vim':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_nextcloud_generic_issue(desc, links) -> IsXIssue:
        if 'nextcloud' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and path_split[1] == 'nextcloud':
                    return IsXIssue.MAYBE

        return IsXIssue.MAYBE

    @staticmethod
    def is_nextcloud_server_issue(desc, links) -> IsXIssue:
        if 'nextcloud server' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and (path_split[1] == 'nextcloud' and path_split[2] == 'server'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_nextcloud_mail_issue(desc, links) -> IsXIssue:
        split_desc = split_and_strip(desc)
        if 'nextcloud' not in split_desc and 'mail' not in split_desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and (path_split[1] == 'nextcloud' and path_split[2] == 'mail'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_nextcloud_calendar_issue(desc, links) -> IsXIssue:
        split_desc = split_and_strip(desc)
        if 'nextcloud' not in split_desc and 'calendar' not in split_desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and (path_split[1] == 'nextcloud' and path_split[2] == 'calendar'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_nextcloud_contacts_issue(desc, links) -> IsXIssue:
        split_desc = split_and_strip(desc)
        if 'nextcloud' not in split_desc and 'contacts' not in split_desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and (path_split[1] == 'nextcloud' and path_split[2] == 'contacts'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_gpac_issue(desc, links) -> IsXIssue:
        if 'gpac' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'gpac':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_redis_issue(desc, links) -> IsXIssue:
        if 'redis' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and (path_first == 'redis' or path_first == 'RedisLabs'):
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_systemd_issue(desc, links) -> IsXIssue:

        if 'systemd' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'systemd':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_django_issue(desc, links) -> IsXIssue:
        check_urls = [
            'docs.djangoproject.com',
            'www.djangoproject.com',
        ]
        if 'django' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_moodle_issue(desc, links) -> IsXIssue:
        check_urls = [
            'git.moodle.org',
            'moodle.org',
        ]
        if 'moodle' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'moodle':
                return IsXIssue.YES
            elif netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_firefox_issue(desc, links) -> IsXIssue:
        check_urls = [
            'bugzilla.mozilla.org',
            'www.mozilla.org',
        ]
        if 'firefox' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_thunderbird_issue(desc, links) -> IsXIssue:
        check_urls = [
            'bugzilla.mozilla.org',
            'www.mozilla.org',
        ]
        if 'thunderbird' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_curl_issue(desc, links) -> IsXIssue:
        check_urls = [
            'security.netapp.com',
            'hackerone.com',
        ]
        split_desc = split_and_strip(desc)
        if ('curl' not in split_desc) and ('libcurl' not in split_desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_glpi_issue(desc, links) -> IsXIssue:
        check_urls = [
            'pluginsGLPI',
            'glpi-project',
        ]

        if 'glpi' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libtiff_issue(desc, links) -> IsXIssue:
        check_urls = [
            'tiffcp.com',
        ]

        if 'libtiff' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'gitlab.com' and path_first == 'libtiff':
                return IsXIssue.YES
            elif netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_grafana_issue(desc, links) -> IsXIssue:
        check_urls = [
            'grafana.com',
        ]

        if 'grafana' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'grafana':
                return IsXIssue.YES
            elif netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_imagemagick_issue(desc, links) -> IsXIssue:
        check_urls = [
            'imagemagick.org',
        ]

        if 'imagemagick' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'ImageMagick':
                return IsXIssue.YES
            elif netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_qemu_issue(desc, links) -> IsXIssue:
        check_urls = [
            'git.qemu.org',
        ]

        if 'qemu' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 3:
                path_third = path_split[3]
                if netloc == 'lists.nongnu.org' and path_third == 'qemu-devel':
                    return IsXIssue.YES
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_wireshark_issue(desc, links) -> IsXIssue:
        check_urls = [
            'www.wireshark.org',
        ]

        if 'wireshark' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'gitlab.com' and path_first == 'wireshark':
                return IsXIssue.YES
            elif netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libvirt_issue(desc, links) -> IsXIssue:
        check_urls = [
            'libvirt.org',
        ]

        if 'libvirt' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'gitlab.com' and path_first == 'libvirt':
                return IsXIssue.YES
            elif netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libraw_issue(desc, links) -> IsXIssue:
        check_urls = [
            'www.libraw.org',
        ]

        if 'libraw' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'LibRaw':
                return IsXIssue.YES
            elif netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_samba_issue(desc, links) -> IsXIssue:
        check_urls = [
            'www.samba.org',
            'bugzilla.samba.org',
        ]

        if 'samba' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_openssl_issue(desc, links) -> IsXIssue:
        check_urls = [
            'git.openssl.org',
            'www.openssl.org',
        ]

        found_flag = 'openssl' in split_and_strip(desc)

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls and found_flag:
                return IsXIssue.YES
            elif netloc in check_urls and not found_flag:
                return IsXIssue.MAYBE

        return IsXIssue.NO

    @staticmethod
    def is_yasm_issue(desc, links) -> IsXIssue:
        if 'yasm' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'yasm':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_emacs_issue(desc, links) -> IsXIssue:
        if 'emacs' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                path_second = path_split[2]
                if netloc == 'git.savannah.gnu.org' and path_second == 'emacs.git':
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libreswan_issue(desc, links) -> IsXIssue:
        if 'libreswan' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'libreswan':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libreoffice_issue(desc, links) -> IsXIssue:
        check_urls = [
            'www.libreoffice.org',
        ]

        if 'libreoffice' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_sudo_issue(desc, links) -> IsXIssue:
        check_urls = [
            'www.sudo.ws',
        ]

        if 'sudo' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'sudo-project':
                return IsXIssue.YES
            elif netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_podofo_issue(desc, links) -> IsXIssue:
        if 'podofo' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'podofo':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_opensearch_issue(desc, links) -> IsXIssue:
        if 'opensearch' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'opensearch-project':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libheif_issue(desc, links) -> IsXIssue:
        if 'libheif' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and (path_split[1] == 'strukturag' and path_split[2] == 'libheif'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_flask_issue(desc, links) -> IsXIssue:
        if 'flask' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and (path_split[1] == 'pallets' and path_split[2] == 'flask'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_cups_filters_issue(desc, links) -> IsXIssue:
        if 'cups-filters' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'OpenPrinting' and path_split[2] == 'cups-filters'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_lua_issue(desc, links) -> IsXIssue:
        check_urls = [
            'www.lua.org',
        ]

        if 'lua' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'lua':
                return IsXIssue.YES
            elif netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_nginx_issue(desc, links) -> IsXIssue:
        if 'nginx' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'nginx':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_tcpdump_issue(desc, links) -> IsXIssue:
        if 'tcpdump' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'the-tcpdump-group' and path_split[2] == 'tcpdump'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_tmux_issue(desc, links) -> IsXIssue:
        if 'tmux' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'tmux' and path_split[2] == 'tmux'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_flatpak_issue(desc, links) -> IsXIssue:
        if 'flatpak' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'flatpak' and path_split[2] == 'flatpak'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_runc_issue(desc, links) -> IsXIssue:
        if 'runc' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'opencontainers' and path_split[2] == 'runc'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_moby_issue(desc, links) -> IsXIssue:
        if 'moby' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and path_split[1] == 'moby':
                    return IsXIssue.MAYBE

        return IsXIssue.MAYBE

    @staticmethod
    def is_libssh_issue(desc, links) -> IsXIssue:
        check_urls = [
            'www.libssh.org',
        ]

        if 'libssh' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_c_ares_issue(desc, links) -> IsXIssue:
        if 'c-ares' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'c-ares' and path_split[2] == 'c-ares'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_avahi_issue(desc, links) -> IsXIssue:
        if 'avahi' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'lathiat' and path_split[2] == 'avahi'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_opensc_issue(desc, links) -> IsXIssue:
        if 'opensc' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'opensc':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_grpc_issue(desc, links) -> IsXIssue:
        if 'grpc' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'grpc':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libjxl_issue(desc, links) -> IsXIssue:
        if 'libjxl' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'libjxl':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libexpat_issue(desc, links) -> IsXIssue:
        if 'libexpat' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'libexpat':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_openldap_issue(desc, links) -> IsXIssue:
        check_urls = [
            'git.openldap.org',
            'bugs.openldap.org',
        ]

        if 'openldap' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_netty_issue(desc, links) -> IsXIssue:
        if 'netty' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'netty':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_nettle_issue(desc, links) -> IsXIssue:
        if 'nettle' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'git.lysator.liu.se' and path_first == 'nettle':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_pypdf_issue(desc, links) -> IsXIssue:
        if 'pypdf' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'py-pdf' and path_split[2] == 'pypdf'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE
