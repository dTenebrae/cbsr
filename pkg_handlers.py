import os
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
                'is_kernel': True,  # убрать, потому как ничто не ядро, кроме ядра
                'stapel_name': 'kernel-lt',
                'nvr_list': [self.get_latest_rpm_data("kernel-lt", tag).get('version', "") for tag in self.tags],
                'check_patch': True,
                'assigned_to': int(self.users_dict['artem.chernyshev']),
                'watchers': [int(self.users_dict['artem.chernyshev'])],
            },
            'vim': {
                'check_func': self.is_vim_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'vim',
                'nvr_list': [self.get_latest_rpm_data("vim", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['artem.chernyshev']),
                'watchers': [int(self.users_dict['artem.chernyshev'])],
            },
            'nextcloud': {
                'check_func': self.is_nextcloud_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'nextcloud',
                'nvr_list': [self.get_latest_rpm_data("nextcloud", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'gpac': {
                'check_func': self.is_gpac_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'gpac',
                'nvr_list': [self.get_latest_rpm_data("gpac", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'redis': {
                'check_func': self.is_redis_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'redis',
                'nvr_list': [self.get_latest_rpm_data("redis", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'systemd': {
                'check_func': self.is_systemd_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'systemd',
                'nvr_list': [self.get_latest_rpm_data("systemd", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'django': {
                'check_func': self.is_django_issue,
                'cve_counter': 0,
                'is_kernel': False,
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
                'is_kernel': False,
                'stapel_name': 'moodle',
                'nvr_list': [self.get_latest_rpm_data("moodle", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vladislav.mitin']),
                                       int(self.users_dict['ilia.polyvyanyy'])]),
                'watchers': None,
            },
            'firefox': {
                'check_func': self.is_mozilla_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'firefox',
                'nvr_list': [self.get_latest_rpm_data("firefox", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': [int(self.users_dict['oleg.shaposhnikov'])],
            },
            'thunderbird': {
                'check_func': self.is_mozilla_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'thunderbird',
                'nvr_list': [self.get_latest_rpm_data("thunderbird", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': [int(self.users_dict['oleg.shaposhnikov'])],
            },
            'curl': {
                'check_func': self.is_curl_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'curl',
                'nvr_list': [self.get_latest_rpm_data("curl", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'glpi': {
                'check_func': self.is_glpi_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'glpi',
                'nvr_list': [self.get_latest_rpm_data("glpi", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['ilia.polyvyanyy']),
                'watchers': None,
            },
            'libtiff': {
                'check_func': self.is_libtiff_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'libtiff',
                'nvr_list': [self.get_latest_rpm_data("libtiff", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'grafana': {
                'check_func': self.is_grafana_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'grafana',
                'nvr_list': [self.get_latest_rpm_data("grafana", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'imagemagick': {
                'check_func': self.is_imagemagick_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'ImageMagick',
                'nvr_list': [self.get_latest_rpm_data("ImageMagick", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'qemu': {
                'check_func': self.is_qemu_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'qemu',
                'nvr_list': [self.get_latest_rpm_data("qemu", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'wireshark': {
                'check_func': self.is_wireshark_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'wireshark',
                'nvr_list': [self.get_latest_rpm_data("wireshark", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'libvirt': {
                'check_func': self.is_libvirt_issue,
                'cve_counter': 0,
                'is_kernel': False,
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
                'is_kernel': False,
                'stapel_name': 'LibRaw',
                'nvr_list': [self.get_latest_rpm_data("LibRaw", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'samba': {
                'check_func': self.is_samba_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'samba',
                'nvr_list': [self.get_latest_rpm_data("samba", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['dmitry.safonov']),
                'watchers': None,
            },
            'openssl': {
                'check_func': self.is_openssl_issue,
                'cve_counter': 0,
                'is_kernel': False,
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
                'is_kernel': False,
                'stapel_name': 'yasm',
                'nvr_list': [self.get_latest_rpm_data("yasm", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'emacs': {
                'check_func': self.is_emacs_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'emacs',
                'nvr_list': [self.get_latest_rpm_data("emacs", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'libreswan': {
                'check_func': self.is_libreswan_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'libreswan',
                'nvr_list': [self.get_latest_rpm_data("libreswan", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'libreoffice': {
                'check_func': self.is_libreoffice_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'libreoffice',
                'nvr_list': [self.get_latest_rpm_data("libreoffice", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'sudo': {
                'check_func': self.is_sudo_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'sudo',
                'nvr_list': [self.get_latest_rpm_data("sudo", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'podofo': {
                'check_func': self.is_podofo_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'podofo',
                'nvr_list': [self.get_latest_rpm_data("podofo", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['alexey.rodionov']),
                'watchers': None,
            },
            'opensearch': {
                'check_func': self.is_opensearch_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'opensearch',
                'nvr_list': [self.get_latest_rpm_data("opensearch", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'libheif': {
                'check_func': self.is_libheif_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'libheif',
                'nvr_list': [self.get_latest_rpm_data("libheif", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'flask': {
                'check_func': self.is_flask_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'python-flask',
                'nvr_list': [self.get_latest_rpm_data("python-flask", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'cups-filters': {
                'check_func': self.is_cups_filters_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'cups-filters',
                'nvr_list': [self.get_latest_rpm_data("cups-filters", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladislav.mitin']),
                'watchers': None,
            },
            'lua': {
                'check_func': self.is_lua_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'lua',
                'nvr_list': [self.get_latest_rpm_data("lua", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': int(self.users_dict['vladimir.chirkin']),
                'watchers': None,
            },
            'nginx': {
                'check_func': self.is_nginx_issue,
                'cve_counter': 0,
                'is_kernel': False,
                'stapel_name': 'nginx',
                'nvr_list': [self.get_latest_rpm_data("nginx", tag).get('version', "") for tag in self.tags],
                'check_patch': False,
                'assigned_to': choice([int(self.users_dict['vitaly.peshcherov']),
                                       int(self.users_dict['vladislav.mitin'])]),
                'watchers': None,
            },
        }

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
        """
        Проверка на то, что уязвимость относится к vim
        """
        if 'vim' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'vim':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_nextcloud_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к nextcloud
        """

        if 'nextcloud' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'nextcloud':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_gpac_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к gpac
        """

        if 'gpac' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'gpac':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_redis_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к redis
        """

        if 'redis' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and (path_first == 'redis' or path_first == 'RedisLabs'):
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_systemd_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к systemd
        """

        if 'systemd' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'systemd':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_django_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к django
        """
        check_urls = [
            'docs.djangoproject.com',
            'www.djangoproject.com',
        ]
        if 'django' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_moodle_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к moodle
        """
        check_urls = [
            'git.moodle.org',
            'moodle.org',
        ]
        if 'moodle' not in desc:
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
    def is_mozilla_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к mozilla
        """
        check_urls = [
            'bugzilla.mozilla.org',
            'www.mozilla.org',
        ]
        if ('firefox' not in desc) or ('thunderbird' not in desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_curl_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к curl
        """
        check_urls = [
            'security.netapp.com',
            'hackerone.com',
        ]
        if ('curl' not in desc) and ('libcurl' not in desc):
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_glpi_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к glpi
        """

        check_urls = [
            'pluginsGLPI',
            'glpi-project',
        ]

        if 'glpi' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libtiff_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к libtiff
        """

        check_urls = [
            'tiffcp.com',
        ]

        if 'libtiff' not in desc:
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
        """
        Проверка на то, что уязвимость относится к grafana
        """

        check_urls = [
            'grafana.com',
        ]

        if 'grafana' not in desc:
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
        """
        Проверка на то, что уязвимость относится к imagemagick
        """

        check_urls = [
            'imagemagick.org',
        ]

        if 'imagemagick' not in desc:
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
        """
        Проверка на то, что уязвимость относится к qemu
        """

        check_urls = [
            'git.qemu.org',
        ]

        if 'qemu' not in desc:
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
        """
        Проверка на то, что уязвимость относится к wireshark
        """

        check_urls = [
            'www.wireshark.org',
        ]

        if 'wireshark' not in desc:
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
        """
        Проверка на то, что уязвимость относится к libvirt
        """

        check_urls = [
            'libvirt.org',
        ]

        if 'libvirt' not in desc:
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
        """
        Проверка на то, что уязвимость относится к libraw
        """

        check_urls = [
            'www.libraw.org',
        ]

        if 'libraw' not in desc:
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
        """
        Проверка на то, что уязвимость относится к samba
        """

        check_urls = [
            'www.samba.org',
            'bugzilla.samba.org',
        ]

        if 'samba' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_openssl_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к libraw
        """

        check_urls = [
            'git.openssl.org',
            'www.openssl.org',
        ]

        found_flag = 'openssl' in desc

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls and found_flag:
                return IsXIssue.YES
            elif netloc in check_urls and not found_flag:
                return IsXIssue.MAYBE

        return IsXIssue.NO

    @staticmethod
    def is_yasm_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к libraw
        """

        if 'yasm' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'yasm':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_emacs_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к emacs
        """

        if 'emacs' not in desc:
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
        """
        Проверка на то, что уязвимость относится к libreswan
        """

        if 'libreswan' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'libreswan':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libreoffice_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к libraw
        """

        check_urls = [
            'www.libreoffice.org',
        ]

        if 'libreoffice' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            if netloc in check_urls:
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_sudo_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к sudo
        """

        check_urls = [
            'www.sudo.ws',
        ]

        if 'sudo' not in desc:
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
        """
        Проверка на то, что уязвимость относится к podofo
        """

        if 'podofo' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'podofo':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_opensearch_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к opensearch
        """

        if 'opensearch' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'opensearch-project':
                return IsXIssue.YES

        return IsXIssue.MAYBE

    @staticmethod
    def is_libheif_issue(desc, links) -> IsXIssue:
        """
        Проверка на то, что уязвимость относится к libheif
        """

        if 'libheif' not in desc:
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
        """
        Проверка на то, что уязвимость относится к flask
        """

        if 'flask' not in desc:
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
        """
        Проверка на то, что уязвимость относится к cups-filters
        """

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
        """
        Проверка на то, что уязвимость относится к lua
        """

        check_urls = [
            'www.lua.org',
        ]

        if 'lua' not in desc:
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
        """
        Проверка на то, что уязвимость относится к nginx
        """

        if 'nginx' not in desc:
            return IsXIssue.NO

        for link in links:
            netloc = parse.urlparse(link).netloc
            path_first = parse.urlparse(link).path.split('/')[1]
            if netloc == 'github.com' and path_first == 'nginx':
                return IsXIssue.YES

        return IsXIssue.MAYBE
