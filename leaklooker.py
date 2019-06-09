from hurry.filesize import size
from bs4 import BeautifulSoup
from colorama import Fore
import argparse
import shodan
import json
import sys

SHODAN_API_KEY = ''

print(r"""
         ,
         )\
        /  \
       '  # '
       ',  ,'
         `'

         ,
         )\
        /  \
       '  ~ ' 
       ',  ,'
         `'
LeakLooker - Find open databases
https://medium.com/@woj_ciech https://github.com/woj-ciech/
Example: python leaklooker.py --mongodb --couchdb --kibana --elastic --first 21 --last 37""")

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

group = parser.add_argument_group("Pages")

parser.add_argument("--elastic", help="Elastic search", action='store_true')
parser.add_argument("--couchdb", help="CouchDB", action='store_true')
parser.add_argument("--mongodb", help="MongoDB", action='store_true')
parser.add_argument("--samba", help="Samba", action='store_true')
parser.add_argument("--gitlab", help="Gitlab", action='store_true')
parser.add_argument("--gogs", help="Gogs", action='store_true')
parser.add_argument("--gitea", help="Gitea", action='store_true')
parser.add_argument("--rsync", help="Rsync", action='store_true')
parser.add_argument("--jenkins", help="Jenkins", action='store_true')
parser.add_argument("--sonarqube", help="SonarQube", action='store_true')
parser.add_argument('--kibana', help='Kibana', action='store_true')
parser.add_argument('--mattermost', help='Mattermost', action='store_true')
parser.add_argument('--rocketchat', help='Rocketchat', action='store_true')
parser.add_argument('--redmine', help='Redmine', action='store_true')
parser.add_argument('--otrs', help='OTRS', action='store_true')
parser.add_argument('--jira', help='Jira', action='store_true')

parser.add_argument("--query", help="Additional query or filter for Shodan", default="")

group.add_argument('--first', help='First current_page', default=None, type=int)
group.add_argument('--last', help='Last current_page', default=None, type=int)

args = parser.parse_args()
first = args.first
last = args.last

if first and last is None:
    print("Correct current_pages")
    sys.exit()
elif last and first is None:
    print('Correct current_pages')
    sys.exit()
elif first is None and last is None:
    print("Choose current_pages to search")
    sys.exit()
elif first > last:
    print('Correct current_pages')
    sys.exit()
else:
    last = last + 1


def shodan_query(query, page):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        result = api.search(query + ' ' + args.query, page=page)
    except shodan.APIError as e:
        print(Fore.RED + e.value + Fore.RESET)
        return False

    if len(result['matches']) > 0:
        print('Found ' + str(result['total']) + " results")
    else:
        print("Nothing was found")
        return False

    return result


def format_link(service_data):
    if str(service_data['port']) == '443':
        print(Fore.LIGHTGREEN_EX + "https://" + service_data['ip_str'] + Fore.RESET)
    elif str(service_data['port']) == '80':
        print(Fore.LIGHTGREEN_EX + "http://" + service_data['ip_str'] + Fore.RESET)
    else:
        print(Fore.LIGHTGREEN_EX + "http://" + service_data['ip_str'] + ':' + str(service_data['port']) + Fore.RESET)


if args.elastic:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------Elastic - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('product:elastic port:9200', current_page)

        if results is not False:
            for service in results['matches']:
                try:
                    if service['elastic']['cluster']['indices']['store']['size_in_bytes'] > 217000000:
                        print("IP: http://" + Fore.LIGHTGREEN_EX + service['ip_str'] + ':' + str(
                            service['port']) + '/_cat/indices?v' + Fore.RESET)

                        if service['hostnames']:
                            print("Hostname")
                            for hostname in service['hostnames']:
                                print(Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                        print("Size: " + Fore.LIGHTGREEN_EX + size(
                            service['elastic']['cluster']['indices']['store']['size_in_bytes']) + Fore.RESET)
                        try:
                            print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                        except:
                            print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)

                        print("Indices: ")
                        for indice, info in service['elastic']['indices'].items():
                            print(Fore.GREEN + indice + Fore.RESET)
                        print("-----------------------------")
                except KeyError:
                    pass

if args.couchdb:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------CouchDB - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('product:couchdb 200 OK', current_page)

        if results is not False:
            for service in results['matches']:
                try:
                    response = service['data'].splitlines()

                    for line in response:
                        if line.startswith("{"):
                            json_data = json.loads(line)

                            if len(json_data['dbs']) < 20 and 'compromised' not in service['tags']:
                                print("IP: http://" + Fore.YELLOW + service['ip_str'] + ':' + str(
                                    service['port']) + '/_utils' + Fore.RESET)

                                if service['hostnames']:
                                    print("Hostname")
                                    for hostname in service['hostnames']:
                                        print(Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)
                                try:
                                    print('Country: ' + Fore.LIGHTBLUE_EX + service['location'][
                                        'country_name'] + Fore.RESET)
                                except:
                                    print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)

                                print("Databases")
                                for db in json_data['dbs']:
                                    print(Fore.LIGHTYELLOW_EX + db + Fore.RESET)

                            print("-----------------------------")
                except KeyError:
                    pass

if args.mongodb:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------MongoDB - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('product:MongoDB', current_page)

        if results is not False:
            for service in results['matches']:
                try:
                    if service['mongodb']['listDatabases']['totalSize'] > 217000000:
                        print("IP: " + Fore.LIGHTBLUE_EX + service['ip_str'] + Fore.RESET)

                        if service['hostnames']:
                            print("Hostname")
                            for hostname in service['hostnames']:
                                print(Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                        print("Size: " + Fore.LIGHTBLUE_EX + size(
                            service['mongodb']['listDatabases']['totalSize']) + Fore.RESET)
                        try:
                            print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                        except:
                            print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)

                        for database in service['mongodb']['listDatabases']['databases']:
                            if database['empty'] != 'true':
                                print("Database name: " + Fore.BLUE + database['name'] + Fore.RESET)
                                print("Size: " + Fore.BLUE + size(database['sizeOnDisk']) + Fore.RESET)
                                print('Collections: ')
                                for collection in database['collections']:
                                    print(Fore.LIGHTBLUE_EX + collection + Fore.RESET)
                        print("-----------------------------")
                except KeyError:
                    pass

if args.samba:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------Samba - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('product:samba disabled', current_page)

        if results is not False:
            try:
                for service in results['matches']:
                    if service['smb']['anonymous']:
                        print(Fore.LIGHTGREEN_EX + service['ip_str'] + ':' + str(service['port']) + Fore.RESET)

                        if service['hostnames']:
                            print("Hostname")
                            for hostname in service['hostnames']:
                                print(Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                        try:
                            print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                        except:
                            print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)

                        print("Shares")
                        for share in service['smb']['shares']:
                            print(Fore.CYAN + share['name'] + " - " + share['comments'] + Fore.RESET)
                        print("-----------------------------")
            except:
                pass

if args.gitlab:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------GitLab - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('http.favicon.hash:1278323681', current_page)

        if results is not False:
            for service in results['matches']:
                if 'http' in service:
                    if "register" in service['http']['html']:
                        format_link(service)

                        if "GitLab Enterprise Edition" in service['http']['html']:
                            print('Edition: ' + Fore.LIGHTGREEN_EX + "Enterprise" + Fore.RESET)
                        else:
                            print('Edition: ' + Fore.LIGHTGREEN_EX + "Community" + Fore.RESET)

                        if service['hostnames']:
                            for hostname in service['hostnames']:
                                print('Hostname: ' + Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                        try:
                            print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                        except:
                            print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)
                        print("-----------------------------")

if args.gogs:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------Gogs - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('http.component:gogs', current_page)

        if results is not False:
            for service in results['matches']:
                if 'http' in service:
                    if "sign_up" in service['http']['html']:
                        format_link(service)

                        if service['hostnames']:
                            print("Hostname")
                            for hostname in service['hostnames']:
                                print(Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                        try:
                            print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                        except:
                            print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)
                        print("-----------------------------")

if args.gitea:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------Gitea - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('gitea', current_page)

        if results is not False:
            for service in results['matches']:
                if 'http' in service:
                    if "sign_up" in service['http']['html']:
                        format_link(service)

                        if service['hostnames']:
                            print("Hostname")
                            for hostname in service['hostnames']:
                                print(Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                        try:
                            print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                        except:
                            print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)
                        print("-----------------------------")

if args.rsync:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------Rsync - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('product:rsyncd', current_page)

        if results is not False:
            for service in results['matches']:
                if not service['rsync']['authentication'] and service['rsync']['modules']:
                    print(Fore.LIGHTGREEN_EX + "rsync://" + service['ip_str'] + ':' + str(service['port']) + Fore.RESET)

                    if service['hostnames']:
                        print("Hostname")
                        for hostname in service['hostnames']:
                            print(Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                    try:
                        print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                    except:
                        print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)

                    print("Modules")
                    for module in [*service['rsync']['modules']]:
                        print(Fore.LIGHTMAGENTA_EX + module + Fore.RESET)
                    print("-----------------------------")

if args.jenkins:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------Jenkins - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('jenkins 200 ok', current_page)

        if results is not False:
            for service in results['matches']:
                executors = set()
                jobs = set()

                if 'http' in service:
                    print(Fore.LIGHTGREEN_EX + "http://" + service['ip_str'] + ':' + str(service['port']) + Fore.RESET)

                    if service['hostnames']:
                        print("Hostname")
                        for hostname in service['hostnames']:
                            print(Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                    try:
                        print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                    except:
                        print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)

                    soup = BeautifulSoup(service['http']['html'], features="html.parser")

                    for project in soup.find_all("a", {"class": "model-link inside"}):
                        if project['href'].startswith("/computer"):
                            splitted = project['href'].split("/")
                            executors.add(splitted[2])

                        elif project['href'].startswith("job"):
                            splitted = project['href'].split("/")
                            jobs.add(splitted[1])

                    print(Fore.BLUE + "Executors" + Fore.RESET)
                    for executor in executors:
                        print(Fore.CYAN + executor + Fore.RESET)

                    print(Fore.BLUE + "Jobs" + Fore.RESET)
                    for job in jobs:
                        print(Fore.CYAN + job + Fore.RESET)
                print("-----------------------------")

if args.sonarqube:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------SonarQube - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('sonarqube', current_page)

        if results is not False:
            for service in results['matches']:
                format_link(service)

                if service['hostnames']:
                    print("Hostname")
                    for hostname in service['hostnames']:
                        print(Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                try:
                    print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                except:
                    print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)
                print("-----------------------------")

if args.kibana:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------Kibana - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('kibana content-length: 217 200 OK', current_page)

        if results is not False:
            try:
                for service in results['matches']:
                    print("IP: http://" + Fore.CYAN + service['ip_str'] + ':' + str(
                        service['port']) + '/app/kibana#/discover?_g=()' + Fore.RESET)

                    if service['hostnames']:
                        print("Hostname")
                        for hostname in service['hostnames']:
                            print(Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                    try:
                        print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                    except:
                        print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)
                        print('---')
                    print('---')
            except:
                pass

if args.mattermost:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------Mattermost - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('http.component:mattermost', current_page)

        if results is not False:
            for service in results['matches']:
                if 'http' in service:
                    if "signup_user_complete" in service['http']['html']:
                        format_link(service)

                        if service['hostnames']:
                            print("Hostname")
                            for hostname in service['hostnames']:
                                print(Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                        try:
                            print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                        except:
                            print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)
                        print("-----------------------------")

if args.rocketchat:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------Rocketchat - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('http.favicon.hash:225632504', current_page)

        if results is not False:
            for service in results['matches']:
                if 'http' in service:
                    format_link(service)

                    if service['hostnames']:
                        print("Hostname")
                        for hostname in service['hostnames']:
                            print(Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                    try:
                        print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                    except:
                        print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)
                    print("-----------------------------")

if args.redmine:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------Redmine - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('http.component:redmine', current_page)

        if results is not False:
            for service in results['matches']:
                if 'http' in service:
                    if "/account/register" in service['http']['html']:
                        format_link(service)

                        if service['hostnames']:
                            for hostname in service['hostnames']:
                                print('Hostname: ' + Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                        try:
                            print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                        except:
                            print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)
                        print("-----------------------------")

if args.otrs:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------OTRS - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('http.component:otrs', current_page)

        if results is not False:
            for service in results['matches']:
                if 'http' in service:
                    if "Signup" in service['http']['html']:
                        format_link(service)

                        if service['hostnames']:
                            for hostname in service['hostnames']:
                                print('Hostname: ' + Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                        try:
                            print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                        except:
                            print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)
                        print("-----------------------------")

if args.jira:
    for current_page in range(first, last):
        print(Fore.RED + '----------------------------------Jira - Page ' + str(
            current_page) + '--------------------------------' + Fore.RESET)

        results = shodan_query('http.component:"atlassian jira"', current_page)

        if results is not False:
            for service in results['matches']:
                if 'http' in service:
                    if "/issues/" in service['http']['html'] or "/Signup" in service['http']['html']:
                        format_link(service)

                        if service['hostnames']:
                            for hostname in service['hostnames']:
                                print('Hostname: ' + Fore.LIGHTYELLOW_EX + hostname + Fore.RESET)

                        try:
                            print('Country: ' + Fore.LIGHTBLUE_EX + service['location']['country_name'] + Fore.RESET)
                        except:
                            print('Country: ' + Fore.RED + 'Unknown' + Fore.RESET)
                        print("-----------------------------")
