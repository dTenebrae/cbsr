import os
import re
import json
import koji
from enum import Enum
from random import choice
import urllib.parse as parse
from itertools import zip_longest
from dotenv import dotenv_values

# Get the path to the directory this file is in
ENV_PATH = os.path.abspath(os.path.dirname(__file__))

credentials = dotenv_values(f"{ENV_PATH}/.env")

USERS_LIST = f"{os.path.expanduser('.')}/users.json"
TAG_LIST_ST7 = [
    "os73-updates",
    "os73-chromium",
    "os73-kernel",
    "os73-kernel6",
]
TAG_LIST_ST8 = [
    "redos80-updates",
]
KOJI7_URL = credentials['KOJI7_URL']
KOJI8_URL = credentials['KOJI8_URL']


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
            if char == '~':
                result_str += '.'
                continue
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

    @staticmethod
    def get_latest_rpm_data(package_name, tag_name, session, deep=True) -> dict:
        """
        На входе получает имя пакета, на выходе отдает dict с информацией по нему
        :param package_name: Имя пакета
        :param tag_name: Тег, в котором проверяем
        :param session: объект сессии koji
        :param deep: Флаг, какую логику использовать для поиска последнего пакета.
        В случае False будет брать последней по дате, что может быть не слишком удачным выбором
        :return: dict с инфой по пакету в случае успеха, пустой dict в противном случае
        """
        if deep:
            package_list_raw = session.listTagged(tag_name['id'], package=package_name)
            if not package_list_raw:
                # на случай если не нашли в теге, ищем через наследование по простому
                package_list = session.getLatestRPMS(tag_name['id'], arch='src', package=package_name)[1]
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
            package_list = session.getLatestRPMS(tag_name['id'], arch='src', package=package_name)[1]

        return package_list[0] if package_list else {}

    def __init__(self):

        with open(USERS_LIST) as f:
            self.users_dict = json.loads(f.read())

        self.session_st7 = koji.ClientSession(KOJI7_URL)
        self.session_st8 = koji.ClientSession(KOJI8_URL)

        self.tags = [(self.session_st7.getTag(tag), self.session_st7) for tag in TAG_LIST_ST7]
        self.tags.extend([(self.session_st8.getTag(tag), self.session_st8) for tag in TAG_LIST_ST8])

        self.pkgs_data = {
            'kernel': {
                'check_func': self.is_kernel_issue,
                'cve_counter': 0,
                'stapel_name': 'kernel-lt',
                'nvr_list': [self.get_latest_rpm_data("kernel-lt", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': True,
                'assigned_to': int(self.users_dict['artem.chernyshev']),
                'watchers': [int(self.users_dict['artem.chernyshev'])],
            },
            'Vim': {
                'check_func': self.is_vim_issue,
                'cve_counter': 0,
                'stapel_name': 'vim',
                'nvr_list': [self.get_latest_rpm_data("vim", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilya.leontiev']),
                'watchers': None,
            },
            'nextcloud': {
                'check_func': self.is_nextcloud_generic_issue,
                'cve_counter': 0,
                'stapel_name': 'nextcloud',
                'nvr_list': [self.get_latest_rpm_data("nextcloud", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'nextcloud-server': {
                'check_func': self.is_nextcloud_server_issue,
                'cve_counter': 0,
                'stapel_name': 'nextcloud',
                'nvr_list': [self.get_latest_rpm_data("nextcloud", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'nextcloud-mail': {
                'check_func': self.is_nextcloud_mail_issue,
                'cve_counter': 0,
                'stapel_name': 'nextcloud-app-mail',
                'nvr_list': [self.get_latest_rpm_data("nextcloud-app-mail", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'nextcloud-calendar': {
                'check_func': self.is_nextcloud_calendar_issue,
                'cve_counter': 0,
                'stapel_name': 'nextcloud-app-calendar',
                'nvr_list': [self.get_latest_rpm_data("nextcloud-app-calendar", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'nextcloud-contacts': {
                'check_func': self.is_nextcloud_contacts_issue,
                'cve_counter': 0,
                'stapel_name': 'nextcloud-app-contacts',
                'nvr_list': [self.get_latest_rpm_data("nextcloud-app-contacts", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'gpac': {
                'check_func': self.is_gpac_issue,
                'cve_counter': 0,
                'stapel_name': 'gpac',
                'nvr_list': [self.get_latest_rpm_data("gpac", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': None,
            },
            'redis': {
                'check_func': self.is_redis_issue,
                'cve_counter': 0,
                'stapel_name': 'redis',
                'nvr_list': [self.get_latest_rpm_data("redis", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'systemd': {
                'check_func': self.is_systemd_issue,
                'cve_counter': 0,
                'stapel_name': 'systemd',
                'nvr_list': [self.get_latest_rpm_data("systemd", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'django': {
                'check_func': self.is_django_issue,
                'cve_counter': 0,
                'stapel_name': 'python-django',
                'nvr_list': [self.get_latest_rpm_data("python-django", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vitaly.peshcherov']),
                                       int(self.users_dict['ilia.polyvyanyy'])]),
                'watchers': None,
            },
            'moodle': {
                'check_func': self.is_moodle_issue,
                'cve_counter': 0,
                'stapel_name': 'moodle',
                'nvr_list': [self.get_latest_rpm_data("moodle", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vladislav.mitin']),
                                       int(self.users_dict['ilia.polyvyanyy'])]),
                'watchers': None,
            },
            'Firefox': {
                'check_func': self.is_firefox_issue,
                'cve_counter': 0,
                'stapel_name': 'firefox',
                'nvr_list': [self.get_latest_rpm_data("firefox", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': [int(self.users_dict['oleg.shaposhnikov'])],
            },
            'Thunderbird': {
                'check_func': self.is_thunderbird_issue,
                'cve_counter': 0,
                'stapel_name': 'thunderbird',
                'nvr_list': [self.get_latest_rpm_data("thunderbird", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': [int(self.users_dict['oleg.shaposhnikov'])],
            },
            'cURL': {
                'check_func': self.is_curl_issue,
                'cve_counter': 0,
                'stapel_name': 'curl',
                'nvr_list': [self.get_latest_rpm_data("curl", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': None,
            },
            'glpi': {
                'check_func': self.is_glpi_issue,
                'cve_counter': 0,
                'stapel_name': 'glpi',
                'nvr_list': [self.get_latest_rpm_data("glpi", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': None,
            },
            'libtiff': {
                'check_func': self.is_libtiff_issue,
                'cve_counter': 0,
                'stapel_name': 'libtiff',
                'nvr_list': [self.get_latest_rpm_data("libtiff", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'grafana': {
                'check_func': self.is_grafana_issue,
                'cve_counter': 0,
                'stapel_name': 'grafana',
                'nvr_list': [self.get_latest_rpm_data("grafana", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vitaly.peshcherov']),
                'watchers': None,
            },
            'ImageMagick': {
                'check_func': self.is_imagemagick_issue,
                'cve_counter': 0,
                'stapel_name': 'ImageMagick',
                'nvr_list': [self.get_latest_rpm_data("ImageMagick", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'qemu': {
                'check_func': self.is_qemu_issue,
                'cve_counter': 0,
                'stapel_name': 'qemu',
                'nvr_list': [self.get_latest_rpm_data("qemu", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['oleg.sviridov']),
                'watchers': None,
            },
            'Wireshark': {
                'check_func': self.is_wireshark_issue,
                'cve_counter': 0,
                'stapel_name': 'wireshark',
                'nvr_list': [self.get_latest_rpm_data("wireshark", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['oleg.sviridov']),
                'watchers': None,
            },
            'libvirt': {
                'check_func': self.is_libvirt_issue,
                'cve_counter': 0,
                'stapel_name': 'libvirt',
                'nvr_list': [self.get_latest_rpm_data("libvirt", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vitaly.peshcherov']),
                                       int(self.users_dict['dmitry.safonov'])]),
                'watchers': None,
            },
            'libraw': {
                'check_func': self.is_libraw_issue,
                'cve_counter': 0,
                'stapel_name': 'LibRaw',
                'nvr_list': [self.get_latest_rpm_data("LibRaw", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'samba': {
                'check_func': self.is_samba_issue,
                'cve_counter': 0,
                'stapel_name': 'samba',
                'nvr_list': [self.get_latest_rpm_data("samba", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['dmitry.safonov']),
                'watchers': None,
            },
            'openSSL': {
                'check_func': self.is_openssl_issue,
                'cve_counter': 0,
                'stapel_name': 'openssl',
                'nvr_list': [self.get_latest_rpm_data("openssl", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': None,
            },
            'yasm': {
                'check_func': self.is_yasm_issue,
                'cve_counter': 0,
                'stapel_name': 'yasm',
                'nvr_list': [self.get_latest_rpm_data("yasm", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'Emacs': {
                'check_func': self.is_emacs_issue,
                'cve_counter': 0,
                'stapel_name': 'emacs',
                'nvr_list': [self.get_latest_rpm_data("emacs", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['anton.savin']),
                'watchers': None,
            },
            'libreswan': {
                'check_func': self.is_libreswan_issue,
                'cve_counter': 0,
                'stapel_name': 'libreswan',
                'nvr_list': [self.get_latest_rpm_data("libreswan", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['oleg.sviridov']),
                'watchers': None,
            },
            'libreoffice': {
                'check_func': self.is_libreoffice_issue,
                'cve_counter': 0,
                'stapel_name': 'libreoffice',
                'nvr_list': [self.get_latest_rpm_data("libreoffice", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'sudo': {
                'check_func': self.is_sudo_issue,
                'cve_counter': 0,
                'stapel_name': 'sudo',
                'nvr_list': [self.get_latest_rpm_data("sudo", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'podofo': {
                'check_func': self.is_podofo_issue,
                'cve_counter': 0,
                'stapel_name': 'podofo',
                'nvr_list': [self.get_latest_rpm_data("podofo", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'opensearch': {
                'check_func': self.is_opensearch_issue,
                'cve_counter': 0,
                'stapel_name': 'opensearch',
                'nvr_list': [self.get_latest_rpm_data("opensearch", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'libheif': {
                'check_func': self.is_libheif_issue,
                'cve_counter': 0,
                'stapel_name': 'libheif',
                'nvr_list': [self.get_latest_rpm_data("libheif", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'flask': {
                'check_func': self.is_flask_issue,
                'cve_counter': 0,
                'stapel_name': 'python-flask',
                'nvr_list': [self.get_latest_rpm_data("python-flask", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'cups-filters': {
                'check_func': self.is_cups_filters_issue,
                'cve_counter': 0,
                'stapel_name': 'cups-filters',
                'nvr_list': [self.get_latest_rpm_data("cups-filters", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'CUPS': {
                'check_func': self.is_cups_issue,
                'cve_counter': 0,
                'stapel_name': 'cups',
                'nvr_list': [self.get_latest_rpm_data("cups", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'Lua': {
                'check_func': self.is_lua_issue,
                'cve_counter': 0,
                'stapel_name': 'lua',
                'nvr_list': [self.get_latest_rpm_data("lua", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'nginx': {
                'check_func': self.is_nginx_issue,
                'cve_counter': 0,
                'stapel_name': 'nginx',
                'nvr_list': [self.get_latest_rpm_data("nginx", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': None,
            },
            'tcpdump': {
                'check_func': self.is_tcpdump_issue,
                'cve_counter': 0,
                'stapel_name': 'tcpdump',
                'nvr_list': [self.get_latest_rpm_data("tcpdump", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vitaly.peshcherov']),
                                       int(self.users_dict['alexey.rodionov'])]),
                'watchers': None,
            },
            'tmux': {
                'check_func': self.is_tmux_issue,
                'cve_counter': 0,
                'stapel_name': 'tmux',
                'nvr_list': [self.get_latest_rpm_data("tmux", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['artem.chernyshev']),
                'watchers': None,
            },
            'flatpak': {
                'check_func': self.is_flatpak_issue,
                'cve_counter': 0,
                'stapel_name': 'flatpak',
                'nvr_list': [self.get_latest_rpm_data("flatpak", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': None,
            },
            'runc': {
                'check_func': self.is_runc_issue,
                'cve_counter': 0,
                'stapel_name': 'runc',
                'nvr_list': [self.get_latest_rpm_data("runc", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vadim.karyaev']),
                'watchers': None,
            },
            'Kubernetes': {
                'check_func': self.is_kubernetes_issue,
                'cve_counter': 0,
                'stapel_name': 'kubernetes',
                'nvr_list': [self.get_latest_rpm_data("kubernetes", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vadim.karyaev']),
                'watchers': None,
            },
            'Docker': {
                'check_func': self.is_moby_issue,
                'cve_counter': 0,
                'stapel_name': 'docker-ce',
                'nvr_list': [self.get_latest_rpm_data("docker-ce", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vadim.karyaev']),
                'watchers': None,
            },
            'libssh': {
                'check_func': self.is_libssh_issue,
                'cve_counter': 0,
                'stapel_name': 'libssh',
                'nvr_list': [self.get_latest_rpm_data("libssh", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['anton.savin']),
                'watchers': None,
            },
            'c-ares': {
                'check_func': self.is_c_ares_issue,
                'cve_counter': 0,
                'stapel_name': 'c-ares',
                'nvr_list': [self.get_latest_rpm_data("c-ares", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vitaly.peshcherov']),
                                       int(self.users_dict['vladislav.mitin']),
                                       int(self.users_dict['ilia.polyvyanyy']),
                                       ]),
                'watchers': None,
            },
            'Avahi': {
                'check_func': self.is_avahi_issue,
                'cve_counter': 0,
                'stapel_name': 'avahi',
                'nvr_list': [self.get_latest_rpm_data("avahi", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vitaly.peshcherov']),
                                       int(self.users_dict['alexey.rodionov'])]),
                'watchers': None,
            },
            'openSC': {
                'check_func': self.is_opensc_issue,
                'cve_counter': 0,
                'stapel_name': 'opensc',
                'nvr_list': [self.get_latest_rpm_data("opensc", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vitaly.peshcherov']),
                'watchers': None,
            },
            'gRPC': {
                'check_func': self.is_grpc_issue,
                'cve_counter': 0,
                'stapel_name': 'grpc',
                'nvr_list': [self.get_latest_rpm_data("grpc", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['ilia.polyvyanyy']),
                                       int(self.users_dict['dmitry.safonov'])]),
                'watchers': None,
            },
            'libexpat': {
                'check_func': self.is_libexpat_issue,
                'cve_counter': 0,
                'stapel_name': 'expat',
                'nvr_list': [self.get_latest_rpm_data("expat", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['ilia.polyvyanyy']),
                                       int(self.users_dict['alexey.rodionov'])]),
                'watchers': None,
            },
            'libjxl': {
                'check_func': self.is_libjxl_issue,
                'cve_counter': 0,
                'stapel_name': 'jpegxl',
                'nvr_list': [self.get_latest_rpm_data("jpegxl", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'openldap': {
                'check_func': self.is_openldap_issue,
                'cve_counter': 0,
                'stapel_name': 'openldap',
                'nvr_list': [self.get_latest_rpm_data("openldap", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['anton.savin']),
                'watchers': None,
            },
            'Netty': {
                'check_func': self.is_netty_issue,
                'cve_counter': 0,
                'stapel_name': 'netty',
                'nvr_list': [self.get_latest_rpm_data("netty", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'Nettle': {
                'check_func': self.is_nettle_issue,
                'cve_counter': 0,
                'stapel_name': 'nettle',
                'nvr_list': [self.get_latest_rpm_data("nettle", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilya.leontiev']),
                'watchers': None,
            },
            'pyPdf': {
                'check_func': self.is_pypdf_issue,
                'cve_counter': 0,
                'stapel_name': 'pyPdf',
                'nvr_list': [self.get_latest_rpm_data("pyPdf", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilya.leontiev']),
                'watchers': None,
            },
            'Gradle': {
                'check_func': self.is_gradle_issue,
                'cve_counter': 0,
                'stapel_name': 'gradle',
                'nvr_list': [self.get_latest_rpm_data("gradle", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['yaroslav.kokurin']),
                'watchers': None,
            },
            'Ghostscript': {
                'check_func': self.is_ghostscript_issue,
                'cve_counter': 0,
                'stapel_name': 'ghostscript',
                'nvr_list': [self.get_latest_rpm_data("ghostscript", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'pygments': {
                'check_func': self.is_pygments_issue,
                'cve_counter': 0,
                'stapel_name': 'python-pygments',
                'nvr_list': [self.get_latest_rpm_data("python-pygments", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilya.leontiev']),
                'watchers': None,
            },
            'cargo': {
                'check_func': self.is_cargo_issue,
                'cve_counter': 0,
                'stapel_name': 'rust',
                'nvr_list': [self.get_latest_rpm_data("rust", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'rust': {
                'check_func': self.is_rust_issue,
                'cve_counter': 0,
                'stapel_name': 'rust',
                'nvr_list': [self.get_latest_rpm_data("rust", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'unRAR': {
                'check_func': self.is_unrar_issue,
                'cve_counter': 0,
                'stapel_name': 'unrar',
                'nvr_list': [self.get_latest_rpm_data("unrar", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'OpenDKIM': {
                'check_func': self.is_opendkim_issue,
                'cve_counter': 0,
                'stapel_name': 'opendkim',
                'nvr_list': [self.get_latest_rpm_data("opendkim", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['dmitry.safonov']),
                'watchers': None,
            },
            'HAProxy': {
                'check_func': self.is_haproxy_issue,
                'cve_counter': 0,
                'stapel_name': 'haproxy',
                'nvr_list': [self.get_latest_rpm_data("haproxy", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['yaroslav.kokurin']),
                'watchers': None,
            },
            'GitPython': {
                'check_func': self.is_gitpython_issue,
                'cve_counter': 0,
                'stapel_name': 'GitPython',
                'nvr_list': [self.get_latest_rpm_data("GitPython", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilya.leontiev']),
                'watchers': None,
            },
            'djvulibre': {
                'check_func': self.is_djvulibre_issue,
                'cve_counter': 0,
                'stapel_name': 'djvulibre',
                'nvr_list': [self.get_latest_rpm_data("djvulibre", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'nasm': {
                'check_func': self.is_nasm_issue,
                'cve_counter': 0,
                'stapel_name': 'nasm',
                'nvr_list': [self.get_latest_rpm_data("nasm", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['anton.savin']),
                'watchers': None,
            },
            'Poppler': {
                'check_func': self.is_poppler_issue,
                'cve_counter': 0,
                'stapel_name': 'poppler',
                'nvr_list': [self.get_latest_rpm_data("poppler", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'p7zip': {
                'check_func': self.is_p7zip_issue,
                'cve_counter': 0,
                'stapel_name': 'p7zip',
                'nvr_list': [self.get_latest_rpm_data("p7zip", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'Alertmanager': {
                'check_func': self.is_alertmanager_issue,
                'cve_counter': 0,
                'stapel_name': 'golang-github-prometheus-alertmanager',
                'nvr_list': [self.get_latest_rpm_data("golang-github-prometheus-alertmanager",
                                                      tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['dmitry.safonov']),
                'watchers': None,
            },
            'giflib': {
                'check_func': self.is_giflib_issue,
                'cve_counter': 0,
                'stapel_name': 'giflib',
                'nvr_list': [self.get_latest_rpm_data("giflib", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'Salt': {
                'check_func': self.is_salt_issue,
                'cve_counter': 0,
                'stapel_name': 'salt',
                'nvr_list': [self.get_latest_rpm_data("salt", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['anton.savin']),
                'watchers': None,
            },
            'Ruby': {
                'check_func': self.is_ruby_issue,
                'cve_counter': 0,
                'stapel_name': 'ruby',
                'nvr_list': [self.get_latest_rpm_data("ruby", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'Jenkins': {
                'check_func': self.is_jenkins_issue,
                'cve_counter': 0,
                'stapel_name': 'jenkins',
                'nvr_list': [self.get_latest_rpm_data("jenkins", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'ReportLab': {
                'check_func': self.is_reportlab_issue,
                'cve_counter': 0,
                'stapel_name': 'python-reportlab',
                'nvr_list': [self.get_latest_rpm_data("python-reportlab", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilya.leontiev']),
                'watchers': None,
            },
            'Webmin': {
                'check_func': self.is_webmin_issue,
                'cve_counter': 0,
                'stapel_name': 'webmin',
                'nvr_list': [self.get_latest_rpm_data("webmin", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': None,
            },
            'Roundcube': {
                'check_func': self.is_roundcube_issue,
                'cve_counter': 0,
                'stapel_name': 'roundcubemail',
                'nvr_list': [self.get_latest_rpm_data("roundcubemail", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'GNOME-Shell': {
                'check_func': self.is_gnome_shell_issue,
                'cve_counter': 0,
                'stapel_name': 'gnome-shell',
                'nvr_list': [self.get_latest_rpm_data("gnome-shell", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'libwebp': {
                'check_func': self.is_libwebp_issue,
                'cve_counter': 0,
                'stapel_name': 'libwebp',
                'nvr_list': [self.get_latest_rpm_data("libwebp", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'snappy-java': {
                'check_func': self.is_snappy_java_issue,
                'cve_counter': 0,
                'stapel_name': 'snappy-java',
                'nvr_list': [self.get_latest_rpm_data("snappy-java", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['maxim.noskov']),
                'watchers': None,
            },
            'composer': {
                'check_func': self.is_composer_issue,
                'cve_counter': 0,
                'stapel_name': 'composer',
                'nvr_list': [self.get_latest_rpm_data("composer", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vitaly.peshcherov']),
                'watchers': None,
            },
            'OptiPNG': {
                'check_func': self.is_optipng_issue,
                'cve_counter': 0,
                'stapel_name': 'optipng',
                'nvr_list': [self.get_latest_rpm_data("optipng", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['yaroslav.kokurin']),
                'watchers': None,
            },
            'Jetty': {
                'check_func': self.is_jetty_issue,
                'cve_counter': 0,
                'stapel_name': 'jetty',
                'nvr_list': [self.get_latest_rpm_data("jetty", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['maxim.noskov']),
                'watchers': None,
            },
            'mosquitto': {
                'check_func': self.is_mosquitto_issue,
                'cve_counter': 0,
                'stapel_name': 'mosquitto',
                'nvr_list': [self.get_latest_rpm_data("mosquitto", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vitaly.peshcherov']),
                'watchers': None,
            },
            'Vorbis-tools': {
                'check_func': self.is_vorbis_tools_issue,
                'cve_counter': 0,
                'stapel_name': 'vorbis-tools',
                'nvr_list': [self.get_latest_rpm_data("vorbis-tools", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['yaroslav.kokurin']),
                'watchers': None,
            },
            'Codium': {
                'check_func': self.is_codium_issue,
                'cve_counter': 0,
                'stapel_name': 'codium',
                'nvr_list': [self.get_latest_rpm_data("codium", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vadim.karyaev']),
                'watchers': None,
            },
            'Erlang': {
                'check_func': self.is_erlang_issue,
                'cve_counter': 0,
                'stapel_name': 'erlang',
                'nvr_list': [self.get_latest_rpm_data("erlang", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['anton.savin']),
                'watchers': None,
            },
            'Chromium': {
                'check_func': self.is_chromium_issue,
                'cve_counter': 0,
                'stapel_name': 'chromium',
                'nvr_list': [self.get_latest_rpm_data("chromium", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['oleg.sviridov']),
                'watchers': None,
            },
            'ffmpeg': {
                'check_func': self.is_ffmpeg_issue,
                'cve_counter': 0,
                'stapel_name': 'ffmpeg',
                'nvr_list': [self.get_latest_rpm_data("ffmpeg", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'golang': {
                'check_func': self.is_golang_issue,
                'cve_counter': 0,
                'stapel_name': 'golang',
                'nvr_list': [self.get_latest_rpm_data("golang", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vadim.karyaev']),
                'watchers': None,
            },
            'cri-o': {
                'check_func': self.is_cri_o_issue,
                'cve_counter': 0,
                'stapel_name': 'cri-o',
                'nvr_list': [self.get_latest_rpm_data("cri-o", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['anton.savin']),
                'watchers': None,
            },
            'libde265': {
                'check_func': self.is_libde265_issue,
                'cve_counter': 0,
                'stapel_name': 'libde265',
                'nvr_list': [self.get_latest_rpm_data("libde265", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'openssh': {
                'check_func': self.is_openssh_issue,
                'cve_counter': 0,
                'stapel_name': 'openssh',
                'nvr_list': [self.get_latest_rpm_data("openssh", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['oleg.sviridov']),
                'watchers': None,
            },
            'openvpn': {
                'check_func': self.is_openvpn_issue,
                'cve_counter': 0,
                'stapel_name': 'openvpn',
                'nvr_list': [self.get_latest_rpm_data("openvpn", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['oleg.sviridov']),
                'watchers': None,
            },
            'openvswitch': {
                'check_func': self.is_openvswitch_issue,
                'cve_counter': 0,
                'stapel_name': 'openvswitch',
                'nvr_list': [self.get_latest_rpm_data("openvswitch", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'FreeRDP': {
                'check_func': self.is_freerdp_issue,
                'cve_counter': 0,
                'stapel_name': 'freerdp',
                'nvr_list': [self.get_latest_rpm_data("freerdp", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'Clojure': {
                'check_func': self.is_clojure_issue,
                'cve_counter': 0,
                'stapel_name': 'clojure',
                'nvr_list': [self.get_latest_rpm_data("clojure", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vitaly.peshcherov']),
                'watchers': None,
            },
            'FreeIPA': {
                'check_func': self.is_freeipa_issue,
                'cve_counter': 0,
                'stapel_name': 'freeipa',
                'nvr_list': [self.get_latest_rpm_data("freeipa", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilya.leontiev']),
                'watchers': None,
            },
            'Kate': {
                'check_func': self.is_kate_issue,
                'cve_counter': 0,
                'stapel_name': 'kate',
                'nvr_list': [self.get_latest_rpm_data("kate", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'Atril': {
                'check_func': self.is_atril_issue,
                'cve_counter': 0,
                'stapel_name': 'atril',
                'nvr_list': [self.get_latest_rpm_data("atril", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'TinyXML': {
                'check_func': self.is_tinyxml_issue,
                'cve_counter': 0,
                'stapel_name': 'tinyxml',
                'nvr_list': [self.get_latest_rpm_data("tinyxml", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['anton.savin']),
                'watchers': None,
            },
            'Apache': {
                'check_func': self.is_apache_issue,
                'cve_counter': 0,
                'stapel_name': 'httpd',
                'nvr_list': [self.get_latest_rpm_data("httpd", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': None,
            },
            'urllib3': {
                'check_func': self.is_urllib3_issue,
                'cve_counter': 0,
                'stapel_name': 'python-urllib3',
                'nvr_list': [self.get_latest_rpm_data("python-urllib3", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilya.leontiev']),
                'watchers': None,
            },
            'Bind': {
                'check_func': self.is_bind_issue,
                'cve_counter': 0,
                'stapel_name': 'bind',
                'nvr_list': [self.get_latest_rpm_data("bind", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['dmitry.safonov']),
                'watchers': None,
            },
            'Python': {
                'check_func': self.is_python_issue,
                'cve_counter': 0,
                'stapel_name': 'python3',
                'nvr_list': [self.get_latest_rpm_data("python3", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilya.leontiev']),
                'watchers': None,
            },
            'DHCPD': {
                'check_func': self.is_postgresql_issue,
                'cve_counter': 0,
                'stapel_name': 'dhcp',
                'nvr_list': [self.get_latest_rpm_data("dhcp", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['yaroslav.kokurin']),
                'watchers': None,
            },
            'PostgreSQL': {
                'check_func': self.is_dhcpd_issue,
                'cve_counter': 0,
                'stapel_name': 'postgresql',
                'nvr_list': [self.get_latest_rpm_data("postgresql", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['dmitry.safonov']),
                'watchers': None,
            },
            'RPM': {
                'check_func': self.is_rpm_issue,
                'cve_counter': 0,
                'stapel_name': 'rpm',
                'nvr_list': [self.get_latest_rpm_data("rpm", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vitaly.peshcherov']),
                'watchers': None,
            },
            'libgit2': {
                'check_func': self.is_libgit2_issue,
                'cve_counter': 0,
                'stapel_name': 'libgit2',
                'nvr_list': [self.get_latest_rpm_data("libgit2", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vitaly.peshcherov']),
                'watchers': None,
            },
            'Engrampa': {
                'check_func': self.is_engrampa_issue,
                'cve_counter': 0,
                'stapel_name': 'engrampa',
                'nvr_list': [self.get_latest_rpm_data("engrampa", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'tomcat': {
                'check_func': self.is_tomcat_issue,
                'cve_counter': 0,
                'stapel_name': 'tomcat',
                'nvr_list': [self.get_latest_rpm_data("tomcat", tag[0], tag[1]).get('version', "")
                             for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['kirill.ivanov']),
                'watchers': None,
            },
        }

    # Нижеследующие функции проверяют, относится ли уязвимость к соответствующему пакету
    @staticmethod
    def is_kernel_issue(desc, links, cpe) -> IsXIssue:
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

        if cpe and (cpe[0].split(":")[4] == 'linux_kernel'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_vim_issue(desc, links, cpe) -> IsXIssue:
        if 'vim' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'vim':
                return IsXIssue.YES
        if cpe and (cpe[0].split(":")[4] == 'vim'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_nextcloud_generic_issue(desc, links, cpe) -> IsXIssue:
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
    def is_nextcloud_server_issue(desc, links, cpe) -> IsXIssue:
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
    def is_nextcloud_mail_issue(desc, links, cpe) -> IsXIssue:
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
    def is_nextcloud_calendar_issue(desc, links, cpe) -> IsXIssue:
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
    def is_nextcloud_contacts_issue(desc, links, cpe) -> IsXIssue:
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
    def is_gpac_issue(desc, links, cpe) -> IsXIssue:
        if 'gpac' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'gpac':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_redis_issue(desc, links, cpe) -> IsXIssue:
        if 'redis' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and (path_first == 'redis' or path_first == 'RedisLabs'):
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_systemd_issue(desc, links, cpe) -> IsXIssue:

        if 'systemd' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'systemd':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_django_issue(desc, links, cpe) -> IsXIssue:
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
    def is_moodle_issue(desc, links, cpe) -> IsXIssue:
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

        if cpe and (cpe[0].split(":")[4] == 'moodle'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_firefox_issue(desc, links, cpe) -> IsXIssue:
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
    def is_thunderbird_issue(desc, links, cpe) -> IsXIssue:
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
    def is_curl_issue(desc, links, cpe) -> IsXIssue:
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
    def is_glpi_issue(desc, links, cpe) -> IsXIssue:
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
    def is_libtiff_issue(desc, links, cpe) -> IsXIssue:
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
    def is_grafana_issue(desc, links, cpe) -> IsXIssue:
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
    def is_imagemagick_issue(desc, links, cpe) -> IsXIssue:
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
    def is_qemu_issue(desc, links, cpe) -> IsXIssue:
        check_urls = [
            'git.qemu.org',
            'www.qemu.org'
        ]

        if 'qemu' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 3:
                if netloc == 'lists.nongnu.org' and path_split[3] == 'qemu-devel':
                    return IsXIssue.YES
                elif netloc == 'gitlab.com' and path_split[1] == 'qemu-project' and path_split[2] == 'qemu':
                    return IsXIssue.YES
                elif netloc == 'gitlab.com' and path_split[1] == 'birkelund' and path_split[2] == 'qemu':
                    return IsXIssue.YES
                elif netloc == 'bugs.launchpad.net' and path_split[1] == 'qemu':
                    return IsXIssue.YES
            if netloc in check_urls:
                return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'qemu'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_wireshark_issue(desc, links, cpe) -> IsXIssue:
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
    def is_libvirt_issue(desc, links, cpe) -> IsXIssue:
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
    def is_libraw_issue(desc, links, cpe) -> IsXIssue:
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
    def is_samba_issue(desc, links, cpe) -> IsXIssue:
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
    def is_openssl_issue(desc, links, cpe) -> IsXIssue:
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
    def is_yasm_issue(desc, links, cpe) -> IsXIssue:
        if 'yasm' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'yasm':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_emacs_issue(desc, links, cpe) -> IsXIssue:
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
    def is_libreswan_issue(desc, links, cpe) -> IsXIssue:
        if 'libreswan' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'Libreswan.org',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc in check_urls:
                return IsXIssue.YES
            if netloc == 'github.com' and path_first == 'libreswan':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libreoffice_issue(desc, links, cpe) -> IsXIssue:
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
    def is_sudo_issue(desc, links, cpe) -> IsXIssue:
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
    def is_podofo_issue(desc, links, cpe) -> IsXIssue:
        if 'podofo' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'podofo':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_opensearch_issue(desc, links, cpe) -> IsXIssue:
        if 'opensearch' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'opensearch-project':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libheif_issue(desc, links, cpe) -> IsXIssue:
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
    def is_flask_issue(desc, links, cpe) -> IsXIssue:
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
    def is_cups_filters_issue(desc, links, cpe) -> IsXIssue:
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
    def is_cups_issue(desc, links, cpe) -> IsXIssue:
        if 'cups' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'OpenPrinting' and path_split[2] == 'cups'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_lua_issue(desc, links, cpe) -> IsXIssue:
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
    def is_nginx_issue(desc, links, cpe) -> IsXIssue:
        if 'nginx' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'nginx':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_tcpdump_issue(desc, links, cpe) -> IsXIssue:
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
    def is_tmux_issue(desc, links, cpe) -> IsXIssue:
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
    def is_flatpak_issue(desc, links, cpe) -> IsXIssue:
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
    def is_runc_issue(desc, links, cpe) -> IsXIssue:
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
    def is_moby_issue(desc, links, cpe) -> IsXIssue:
        if 'moby' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'moby' and path_split[2] == 'moby'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libssh_issue(desc, links, cpe) -> IsXIssue:
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
    def is_c_ares_issue(desc, links, cpe) -> IsXIssue:
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
    def is_avahi_issue(desc, links, cpe) -> IsXIssue:
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
    def is_opensc_issue(desc, links, cpe) -> IsXIssue:
        if 'opensc' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'opensc':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_grpc_issue(desc, links, cpe) -> IsXIssue:
        if 'grpc' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'grpc':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libjxl_issue(desc, links, cpe) -> IsXIssue:
        if 'libjxl' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'libjxl':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libexpat_issue(desc, links, cpe) -> IsXIssue:
        if 'libexpat' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'libexpat':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_openldap_issue(desc, links, cpe) -> IsXIssue:
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
    def is_netty_issue(desc, links, cpe) -> IsXIssue:
        if 'netty' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'netty':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_nettle_issue(desc, links, cpe) -> IsXIssue:
        if 'nettle' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'git.lysator.liu.se' and path_first == 'nettle':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_pypdf_issue(desc, links, cpe) -> IsXIssue:
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

    @staticmethod
    def is_gradle_issue(desc, links, cpe) -> IsXIssue:
        if 'gradle' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'gradle' and path_split[2] == 'gradle'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_ghostscript_issue(desc, links, cpe) -> IsXIssue:
        check_urls = [
            'git.ghostscript.com',
            'bugs.ghostscript.com',
        ]

        if 'ghostscript' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_pygments_issue(desc, links, cpe) -> IsXIssue:
        if 'pygments' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and (path_split[1] == 'pygments' and path_split[2] == 'pygments'):
                    return IsXIssue.YES
                elif netloc == 'pypi.org' and (path_split[1] == 'project' and path_split[2] == 'Pygments'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_cargo_issue(desc, links, cpe) -> IsXIssue:
        if 'cargo' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'rust-lang' and path_split[2] == 'cargo'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_rust_issue(desc, links, cpe) -> IsXIssue:
        if 'rust' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'rust-lang' and path_split[2] == 'rust'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_unrar_issue(desc, links, cpe) -> IsXIssue:
        if 'unrar' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'pmachapman' and path_split[2] == 'unrar'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_opendkim_issue(desc, links, cpe) -> IsXIssue:
        if 'opendkim' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'trusteddomainproject' and path_split[2] == 'OpenDKIM'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_haproxy_issue(desc, links, cpe) -> IsXIssue:
        check_urls = [
            'www.haproxy.org',
        ]

        if 'haproxy' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'haproxy':
                return IsXIssue.YES
            elif netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_gitpython_issue(desc, links, cpe) -> IsXIssue:
        if 'gitpython' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'gitpython-developers' and path_split[2] == 'GitPython'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_djvulibre_issue(desc, links, cpe) -> IsXIssue:
        if 'djvulibre' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'djvu.sourceforge.net',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2 and (netloc == 'sourceforge.net' and path_split[2] == 'djvu'):
                return IsXIssue.YES
            elif netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_nasm_issue(desc, links, cpe) -> IsXIssue:
        if 'nasm' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'nasm.us',
            'bugzilla.nasm.us',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_poppler_issue(desc, links, cpe) -> IsXIssue:
        if 'poppler' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'gitlab.freedesktop.org' and \
                        (path_split[1] == 'poppler' and path_split[2] == 'poppler'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_p7zip_issue(desc, links, cpe) -> IsXIssue:
        if 'p7zip' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2 and (netloc == 'sourceforge.net' and path_split[2] == 'p7zip'):
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_alertmanager_issue(desc, links, cpe) -> IsXIssue:
        if 'alertmanager' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'prometheus' and path_split[2] == 'alertmanager'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_giflib_issue(desc, links, cpe) -> IsXIssue:
        if 'giflib' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2 and (netloc == 'sourceforge.net' and path_split[2] == 'giflib'):
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_salt_issue(desc, links, cpe) -> IsXIssue:
        if 'salt' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'saltproject.io',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_ruby_issue(desc, links, cpe) -> IsXIssue:
        if 'ruby' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'ruby-lang.org',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_jenkins_issue(desc, links, cpe) -> IsXIssue:
        if 'jenkins' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'www.jenkins.io',
            'jenkins.io',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_reportlab_issue(desc, links, cpe) -> IsXIssue:
        if 'reportlab' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'MrBitBucket' and path_split[2] == 'reportlab-mirror'):
                    return IsXIssue.YES
                if netloc == 'hg.reportlab.com' and \
                        (path_split[1] == 'hg-public' and path_split[2] == 'reportlab'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_webmin_issue(desc, links, cpe) -> IsXIssue:
        if 'webmin' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'webmin.com',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_roundcube_issue(desc, links, cpe) -> IsXIssue:
        if 'roundcube' not in split_and_strip(desc):
            return IsXIssue.NO
        check_urls = [
            'roundcube.net',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')

            if netloc in check_urls:
                return IsXIssue.YES

            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'roundcube' and path_split[2] == 'roundcubemail'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_gnome_shell_issue(desc, links, cpe) -> IsXIssue:
        if ('gnome' not in split_and_strip(desc)) and ('shell' not in split_and_strip(desc)):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'gitlab.gnome.org' and \
                        (path_split[1] == 'GNOME' and path_split[2] == 'gnome-shell'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libwebp_issue(desc, links, cpe) -> IsXIssue:
        if 'libwebp' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'chromium.googlesource.com' and \
                        (path_split[1] == 'webm' and path_split[2] == 'libwebp'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_snappy_java_issue(desc, links, cpe) -> IsXIssue:
        if ('snappy' not in split_and_strip(desc)) and ('java' not in split_and_strip(desc)):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'xerial' and path_split[2] == 'snappy-java'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_composer_issue(desc, links, cpe) -> IsXIssue:
        if 'composer' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'composer' and path_split[2] == 'composer'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_optipng_issue(desc, links, cpe) -> IsXIssue:
        if 'optipng' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'optipng.sourceforge.net',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')

            if netloc in check_urls:
                return IsXIssue.YES

            if len(path_split) > 2:
                if netloc == 'sourceforge.net' and \
                        (path_split[1] == 'projects' and path_split[2] == 'optipng'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_jetty_issue(desc, links, cpe) -> IsXIssue:
        if 'jetty' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'eclipse' and path_split[2] == 'jetty.project'):
                    return IsXIssue.YES
        if cpe and (cpe[0].split(":")[4] == 'jetty'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_mosquitto_issue(desc, links, cpe) -> IsXIssue:
        if 'mosquitto' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'mosquitto.org',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc

            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_vorbis_tools_issue(desc, links, cpe) -> IsXIssue:
        if ('vorbis' not in split_and_strip(desc)) and ('tools' not in split_and_strip(desc)):
            return IsXIssue.NO

        check_urls = [
            'xiph.org',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')

            if netloc in check_urls:
                return IsXIssue.YES

            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'xiph' and path_split[2] == 'vorbis'):
                    return IsXIssue.YES
                elif netloc == 'github.com' and \
                        (path_split[1] == 'xiph' and path_split[2] == 'vorbis-tools'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_kubernetes_issue(desc, links, cpe) -> IsXIssue:
        if 'kubernetes' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'kubernetes' and path_split[2] == 'kubernetes'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'kubernetes'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_codium_issue(desc, links, cpe) -> IsXIssue:
        if ('visual' not in split_and_strip(desc)) and \
                ('studio' not in split_and_strip(desc)) and \
                ('code' not in split_and_strip(desc)):
            return IsXIssue.NO

        if cpe and (cpe[0].split(":")[4] == 'visual_studio_code'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_erlang_issue(desc, links, cpe) -> IsXIssue:
        if 'erlang' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'erlang'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'erlang'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_chromium_issue(desc, links, cpe) -> IsXIssue:
        if 'chromium' not in split_and_strip(desc) or \
                (('google' not in split_and_strip(desc)) and ('chrome' not in split_and_strip(desc))):
            return IsXIssue.NO

        check_urls = [
            'crbug.com',
            'chromereleases.googleblog.com',
            'bugs.chromium.org'
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'chrome'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_ffmpeg_issue(desc, links, cpe) -> IsXIssue:
        if 'ffmpeg' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'patchwork.ffmpeg.org',
        ]
        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'FFmpeg' and path_split[2] == 'FFmpeg'):
                    return IsXIssue.YES
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_golang_issue(desc, links, cpe) -> IsXIssue:
        if 'golang' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'go.dev',
            'pkg.go.dev',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        if cpe and (cpe[0].split(":")[3] == 'golang'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_cri_o_issue(desc, links, cpe) -> IsXIssue:
        if ('cri' not in split_and_strip(desc)) and ('o' not in split_and_strip(desc)):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'cri-o' and path_split[2] == 'cri-o'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[3] == 'kubernetes') \
                and (cpe[0].split(":")[4] == 'cri-o'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libde265_issue(desc, links, cpe) -> IsXIssue:
        if 'libde265' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'strukturag' and path_split[2] == 'libde265'):
                    return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_openssh_issue(desc, links, cpe) -> IsXIssue:
        if 'openssh' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'www.openssh.com',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if netloc in check_urls:
                return IsXIssue.YES

            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'openssh' and path_split[2] == 'openssh-portable'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'openssh'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_openvpn_issue(desc, links, cpe) -> IsXIssue:
        if 'openvpn' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'community.openvpn.net',
            'openvpn.net',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if netloc in check_urls:
                return IsXIssue.YES

            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'OpenVPN' and path_split[2] == 'openvpn'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'openvpn'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_openvswitch_issue(desc, links, cpe) -> IsXIssue:
        if 'openvswitch' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'openvswitch'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'openvswitch'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_freerdp_issue(desc, links, cpe) -> IsXIssue:
        if 'freerdp' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'FreeRDP' and path_split[2] == 'FreeRDP'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'freerdp'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_clojure_issue(desc, links, cpe) -> IsXIssue:
        if 'clojure' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'clojure.atlassian.net',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if netloc in check_urls:
                return IsXIssue.YES

            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'clojure' and path_split[2] == 'clojure'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'clojure'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_freeipa_issue(desc, links, cpe) -> IsXIssue:
        if 'ipa' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'freeipa.org',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'freeipa'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_kate_issue(desc, links, cpe) -> IsXIssue:
        if ('kde' not in split_and_strip(desc)) and ('kate' not in split_and_strip(desc)):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')

            if len(path_split) > 2:
                if netloc == 'apps.kde.org' and \
                        (path_split[1] == 'kate'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'kate'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_atril_issue(desc, links, cpe) -> IsXIssue:
        if 'atril' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'mate-desktop' and path_split[2] == 'atril'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'atril'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_tinyxml_issue(desc, links, cpe) -> IsXIssue:
        if 'tinyxml' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'sourceforge.net' and \
                        (path_split[2] == 'tinyxml'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'tinyxml'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_apache_issue(desc, links, cpe) -> IsXIssue:
        if ('apache' not in split_and_strip(desc)) and ('http' not in split_and_strip(desc)):
            return IsXIssue.NO

        check_urls = [
            'httpd.apache.org',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        if cpe and \
                (cpe[0].split(":")[3] == 'apache' and cpe[0].split(":")[4] == 'http_server'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_urllib3_issue(desc, links, cpe) -> IsXIssue:
        if 'urllib3' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')

            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'urllib3' and path_split[2] == 'urllib3'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'urllib3'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_bind_issue(desc, links, cpe) -> IsXIssue:
        if 'bind' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'kb.isc.org',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'bind'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_python_issue(desc, links, cpe) -> IsXIssue:
        if 'python' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')

            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'python' and path_split[2] == 'cpython'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[3] == 'python' and cpe[0].split(":")[4] == 'python'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_dhcpd_issue(desc, links, cpe) -> IsXIssue:
        if 'dhcpd' not in split_and_strip(desc):
            return IsXIssue.NO

        if cpe and \
                (cpe[0].split(":")[3] == 'isc' and cpe[0].split(":")[4] == 'dhcpd'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_postgresql_issue(desc, links, cpe) -> IsXIssue:
        if 'postgresql' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'www.postgresql.org',
            'git.postgresql.org',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        if cpe and (cpe[0].split(":")[3] == 'postgresql' and cpe[0].split(":")[4] == 'postgresql'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_rpm_issue(desc, links, cpe) -> IsXIssue:
        if 'rpm' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'rpm-software-management' and path_split[2] == 'rpm'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[3] == 'rpm' and cpe[0].split(":")[4] == 'rpm'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libgit2_issue(desc, links, cpe) -> IsXIssue:
        if 'libgit2' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'libgit2' and path_split[2] == 'libgit2'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'libgit2'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_engrampa_issue(desc, links, cpe) -> IsXIssue:
        if 'engrampa' not in split_and_strip(desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_split = parse.urlparse(link).path.split('/')
            if len(path_split) > 2:
                if netloc == 'github.com' and \
                        (path_split[1] == 'mate-desktop' and path_split[2] == 'engrampa'):
                    return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'engrampa'):
            return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_tomcat_issue(desc, links, cpe) -> IsXIssue:
        if 'tomcat' not in split_and_strip(desc):
            return IsXIssue.NO

        check_urls = [
            'list.apache.org',
            'apache.org',
        ]

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        if cpe and (cpe[0].split(":")[4] == 'tomcat'):
            return IsXIssue.YES

        return IsXIssue.MAYBE
