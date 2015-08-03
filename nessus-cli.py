#!/usr/bin/env python

import json
import time
import sys
import getopt
import sqlite3
import requests

# Disable Warning when not verifying SSL certs.
requests.packages.urllib3.disable_warnings()

url = 'https://<HOST>:8834'
verify = False
token = ''
username = '<USERNAME>'
password = '<PASSWORD>'
#email address to recieve status report
email = '<EMAIL>'

conn = sqlite3.connect('/usr/local/scripts/status.db')
con = conn.cursor()

if len(sys.argv) == 1:
  	print("./nessus-cli.py -h")
	exit()
if sys.argv[1] == "-h":
	print ""
	print "#"*34
	print "# \t Nessus api client \t #"
	print "#"*34 
	print "Add Desktop Scan" 
	print "\t"+sys.argv[0]+" add_desktop_scan name description target"
	print ""
	print "Add Server Scan"
       print "\t"+sys.argv[0]+" add_server_scan name description target"
       print ""
	print "List Scans"
       print "\t"+sys.argv[0]+" list_scans"
	print ""
	print "List Subnets"
       print "\t"+sys.argv[0]+" list_subnets"
       print ""
	print "List running scans"
	print "\t"+sys.argv[0]+" list_running_scans"
	print ""
	print "List completed scans"
	print "\t"+sys.argv[0]+" list_completed_scans"
	print ""
	print "Export Scan"
	print "\t"+sys.argv[0]+" export_scan id"
	print ""
	print "Export scans that have not been completed"
	print "\t"+sys.argv[0]+" export_scans"
	print ""
       print ""
       print "Start Scan"
       print "\t"+sys.argv[0]+" launch_scan  id"
       print ""
	print "#"*34
       exit()

def build_url(resource):
   return '{0}{1}'.format(url, resource)
def connect(method, resource, data=None, params=None):
   """
   Send a request
   Send a request to Nessus based on the specified data. If the session token
   is available add it to the request. Specify the content type as JSON and
   convert the data to JSON format.
   """
   headers = {'X-Cookie': 'token={0}'.format(token),
              'content-type': 'application/json'}

   data = json.dumps(data)

   if method == 'POST':
       r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
   elif method == 'PUT':
       r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
   elif method == 'DELETE':
       r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
   else:
       r = requests.get(build_url(resource), params=params, headers=headers, verify=verify)

   # Exit if there is an error.
   if r.status_code != 200:
       e = r.json()
       print e['error']
       sys.exit()

   # When downloading a scan we need the raw contents not the JSON data. 
   if 'download' in resource:
       return r.content

   # All other responses should be JSON data. Return raw content if they are
   # not.
   try:
       return r.json()
   except ValueError:
       return r.content


def login(usr, pwd):
   """
   Login to nessus.
   """

   login = {'username': usr, 'password': pwd}
   data = connect('POST', '/session', data=login)
   return data['token']


def logout():
   """
   Logout of nessus.
   """

   connect('DELETE', '/session')

def list_scans(stat):

	data = connect('GET', '/scans')
	lists = {}
       for s in data['scans']:
		if stat == "all":
               	list = str(s['id']),str(s['name']), str(s['uuid']), str(s['status'])
               	print "\t".join(list)

		elif stat == "completed_dic" and s['status'] == "completed" :
			lists[str(s['id'])] = str(s['uuid'])
				
		elif s['status'] == stat:
			list = str(s['id']),s['name'], s['uuid'], str(s['status'])
                       print "\t".join(list)
	
	return lists

def get_scans():
	data = connect('GET', '/scans')
	for s in data['scans']:
		list = str(s['id']),s['name'], str(s['last_modification_date'])
		print "\t".join(list)

def get_subnets():
       data = connect('GET', '/scans')
       for s in data['scans']:
               list = s['name']
               print list
	
def get_policies():
   """
   Get scan policies
   Get all of the scan policies but return only the title and the uuid of
   each policy.
   """ 
   #data = connect('GET', '/editor/policy/templates')
   #return dict((p['title'], p['uuid']) for p in data['templates'])
   #MY stuuf
   data = connect('GET', '/policies')
   return dict((p['description'], p['template_uuid']) for p in data['policies'])

def  get_policy_id():
   """
   Get scan policy id.
   """
   #data = connect('GET', '/editor/policy/templates')
   #return dict((p['title'], p['uuid']) for p in data['templates'])
   #MY stuff
   data = connect('GET', '/policies')
   return dict((p['description'],p['id']) for p in data['policies'])


def get_history_ids(sid):
   """
   Get history ids
   Create a dictionary of scan uuids and history ids so we can lookup the
   history id by uuid.
   """
   data = connect('GET', '/scans/{0}'.format(sid))

   return dict((h['uuid'], h['history_id']) for h in data['history'])


def get_scan_history(sid, hid):
   """
   Scan history details
   Get the details of a particular run of a scan.
   """
   params = {'history_id': hid}
   data = connect('GET', '/scans/{0}'.format(sid), params)

   return data['info']


def add(name, desc, targets, pid):
   """
   Add a new scan
   Create a new scan using the policy_id, name, description and targets. The
   scan will be created in the default folder for the user. Return the id of
   the newly created scan.
   """

   scan = {'uuid': pid,
           'settings': {
               'name': name,
               'description': desc,
               'text_targets': targets}
           }

   data = connect('POST', '/scans', data=scan)

   return data['scan']


def update(scan_id, name, desc, targets, policy_id, pid=None):
   """
   Update a scan
   Update the name, description, targets, or policy of the specified scan. If
   the name and description are not set, then the policy name and description
   will be set to None after the update. In addition the targets value must
   be set or you will get an "Invalid 'targets' field" error.
   """

   scan = {}
   scan['settings'] = {}
   scan['settings']['name'] = name
   scan['settings']['desc'] = desc
   scan['settings']['policy_id'] = policy_id
   scan['settings']['text_targets'] = targets

   if pid is not None:
       scan['uuid'] = pid

   data = connect('PUT', '/scans/{0}'.format(scan_id), data=scan)

   return data


def launch(sid):
   """
   Launch a scan
   Launch the scan specified by the sid.
   """

   data = connect('POST', '/scans/{0}/launch'.format(sid))

   return data['scan_uuid']


def status(sid, hid):
   """
   Check the status of a scan run
   Get the historical information for the particular scan and hid. Return
   the status if available. If not return unknown.
   """ 

   d = get_scan_history(sid, hid)
   return d['status']


def export_status(sid, fid):
   """
   Check export status
   Check to see if the export is ready for download.
   """

   data = connect('GET', '/scans/{0}/export/{1}/status'.format(sid, fid))

   return data['status'] == 'ready'

def export(sid):
   """
   Make an export request
   Request an export of the scan results for the specified scan and
   historical run. In this case the format is hard coded as nessus but the
   format can be any one of nessus, html, pdf, csv, or db. Once the request
   is made, we have to wait for the export to be ready.
   """

   data = {'format': 'nessus',
           'chapters': 'vuln_hosts_summary'}

   data = connect('POST', '/scans/{0}/export'.format(sid), data=data)

   fid = data['file']

   while export_status(sid, fid) is False:
       time.sleep(5)

   return fid


def download(sid, fid):
   """
   Download the scan results
   Download the scan results stored in the export file specified by fid for
   the scan specified by sid.
   """

   data = connect('GET', '/scans/{0}/export/{1}/download'.format(sid, fid))
   # Set this path to the desired destination of the exported scans
   filename = '/<PATH>/nessus_{0}_{1}.nessus'.format(sid, fid)

   print('Saving scan results to {0}.'.format(filename))
   with open(filename, 'w') as f:
       f.write(data)


def delete(sid):
   """
   Delete a scan
   This deletes a scan and all of its associated history. The scan is not
   moved to the trash folder, it is deleted.
   """

   connect('DELETE', '/scans/{0}'.format(scan_id))


def history_delete(sid, hid):
   """
   Delete a historical scan.
   This deletes a particular run of the scan and not the scan itself. the
   scan run is defined by the history id.
   """

   connect('DELETE', '/scans/{0}/history/{1}'.format(sid, hid))


if __name__ == '__main__':
   	
	#print('Login')
   	token = login(username, password)


	""" 
	Adding Scans
	"""

	if str(sys.argv[1]) == "add_desktop_scan":
   		if not sys.argv[2:]:
               	print "not enough arguments"
			print sys.argv[0]+" -h"
			exit()
		name = str(sys.argv[2])
		if not sys.argv[3:]:
               	print "not enough arguments"
			print sys.argv[0]+" -h"
			exit()
   		desc = str(sys.argv[3])
		if not sys.argv[4:]:
			print "not enough arguments"
               	print sys.argv[0]+" -h"
			exit()
   		target = str(sys.argv[4])

   		print('Adding new desktop scan.')
		policies = get_policies()
		policy = policies['Desktop']
		policyid = get_policy_id()
   		policy_id = policyid['Desktop']
		scan_data = add(name, desc, target, policy)
		scan_id = scan_data['id']
		print('Updating scan with new targets.')
   		update(scan_id, scan_data['name'], scan_data['description'], target, policy_id)


	if str(sys.argv[1]) == "add_server_scan":
               if not sys.argv[2:]:
                       print "not enough arguments"
                       print sys.argv[0]+" -h"
                       exit()
               name = str(sys.argv[2])
               print name
               if not sys.argv[3:]:
                       print "not enough arguments"
                       print sys.argv[0]+" -h"
                       exit()
               desc = str(sys.argv[3])
               print desc
               if not sys.argv[4:]:
                       print "not enough arguments"
                       print sys.argv[0]+" -h"
                       exit()
               target = str(sys.argv[4])
               print target

               print('Adding new server scan.')
               policies = get_policies()
               policy = policies['Server']
               policyid = get_policy_id()
               policy_id = policyid['Server']
               scan_data = add(name, desc, target, policy)
               scan_id = scan_data['id']
               print('Updating scan with new targets.')
               update(scan_id, scan_data['name'], scan_data['description'], target, policy_id)

	if sys.argv[1] == "launch_scan":
		if not sys.argv[2:]:
                       print "not enough arguments"
                       print sys.argv[0]+" -h"
                       exit()
		print('Launching new scan.')
		scan_id = sys.argv[2]
   		launch(scan_id)
   		#history_ids = get_history_ids(scan_id)
   		#history_id = history_ids[scan_uuid]
   		#while status(scan_id, history_id) != 'completed':
   		time.sleep(5)

	"""
	List Scans 
	"""
	if sys.argv[1] == "list_scans":
       	print "List Scans"
   		list_scans("all") 

	if sys.argv[1] == "list_subnets":
		get_subnets()

	if sys.argv[1] == "list_running_scans":
		list_scans("running")

	if sys.argv[1] == "list_completed_scans":
		test = list_scans("completed")	
	

	"""
	Export given scans to a folder for splunk to pickup or for manual examination 
	"""
	if sys.argv[1] == "export_scan":
		if not sys.argv[2]:
			print "No Id specified"
			exit()
		scan_id = sys.argv[2]
		print('Exporting the completed scan.')
   		file_id = export(scan_id)
   		download(scan_id, file_id)

	"""
	Export completed scans to a folder for splunk to pickup or for manual examination 
	"""

	if sys.argv[1]  == "export_scans":
		complete = list_scans("completed_dic")
		for c, u in complete.iteritems():
			#check if we have exported the scan if so then move on
			con.execute('SELECT rowid FROM scans WHERE uuid=?', (u,))
			result = con.fetchone()
			if result is None:
				#print u
				scan_id = c
                               print('Exporting the completed scan.')
                               file_id = export(scan_id)
                               download(scan_id, file_id)
                               con.execute('INSERT INTO scans VALUES (?)', (u,))
				conn.commit()
			#else:
				#print "Exported already"
				
	
	conn.close()
   	#print('Deleting the scan.')
   	#history_delete(scan_id, history_id)
   	#delete(scan_id)

    # if you want the script to log out once done enable this, I dont use it as it logs you out if you are in the web interface when this runs
   	#print('Logout')
   	#logout()
