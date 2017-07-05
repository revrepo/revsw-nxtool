##########################################################################
#
# NUU:BIT CONFIDENTIAL
#
# [2013] - [2015] nuu:bit, Inc.
# All Rights Reserved.
#
# NOTICE:  All information contained herein is, and remains
# the property of nuu:bit, Inc. and its suppliers,
# if any.  The intellectual and technical concepts contained
# herein are proprietary to nuu:bit, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents,
# patents in process, and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this material
# is strictly forbidden unless prior written permission is obtained
# from nuu:bit, Inc.
#

#!/usr/bin/env python
import os
import re
import datetime
import argparse
from datetime import datetime

def get_options():
  parser = argparse.ArgumentParser(
      description='Automaitically generate whitelist rules based on nxtool generated logs.',
      usage='%(prog)s --nxt <path> --cfg <path> [options]')
  parser.add_argument('-x', '--nxt',
      help="Path to nxtool folder [default: %(default)s]",
      metavar='<path>',
      required=False,
      type=str,
      default=os.getcwd(),
      action='store')
  parser.add_argument('-c', '--cfg',
      help="Path to nxapi.json configuration file [default: %(default)s]",
      metavar='<path>',
      required=False,
      type=str,
      default=os.path.join(os.getcwd(), 'nxapi.json'),
      action='store')
  parser.add_argument('-d', '--idates', 
      help="Comma separated or range dates for ES indexes [default: %(default)s]",
      default=datetime.today().strftime('%Y.%m.%d'),
      metavar='<date(s)>',
      required=False,
      type=str,
      action='store')
  parser.add_argument('-s', '--server', 
      help="FQDN to which we should restrict operations.",
      default=None,
      metavar='<str>',
      required=False,
      type=str,
      action='store')
  parser.add_argument('-w', '--wl_rule', 
      help="Generated whiteList rules file path [default: %(default)s]",
      default="./wl_<domain>.rule",
      metavar='<str>',
      required=False,
      type=str,
      action='store')
  argv = parser.parse_args()
  argv.wl_rule = "wl_%s.rule" % argv.server if argv.server != None else "wl.rule"
  return argv
  

def gen_current_stat(args):
  dates = args.idates
  cfg = args.cfg
  server = "-s %s" % (args.server) if args.server != None else ""
  cmd = 'python nxtool.py -x --colors -c %s %s --idates=%s --fullstats > /tmp/autowl.tmp' % (cfg, server, dates)
  res = os.system(cmd)
  if res >> 8 != 0:
    print "Error occured during statistics generation"
    exit(1)

def load_urls_from_stat():
  urls = []
  try:
    fh = open('/tmp/autowl.tmp', 'r')
    for i, line in enumerate(fh):
      m = re.match('^#\s(\/.*)\s\d+\.\d+\%\s?\(total.*\n$', line)
      if m: urls.append(m.group(1))
    fh.close()
    return urls
  except Exception as e:
    print "Exception during loading urls: %s" % (e.message)
    exit(1)

def create_template_file(url):
  try:
    fh = open('/tmp/temp.tpl', 'w')
    fstr = """{
   "_msg" : "auto_gen_temp_file",
   "uri"  : "%s",
   "zone" : "?",
   "id"   : "?"
}""" % (url.replace('"', '\\"'))
    fh.write(fstr)
    fh.close()
  except Exception as e:
    print "Exception during template file creation : %s" % e.message
    exit(1)

def generate_wl_report_for_url(args, url):
  dates = args.idates
  cfg = args.cfg
  server = "-s %s" % (args.server) if args.server != None else ""
  cmd = 'python nxtool.py -c %s %s -t /tmp/temp.tpl --slack --idates=%s --colors > /tmp/wl_report.wl' % (cfg, server, dates)
  res = os.system(cmd)
  if res >> 8 != 0:
    print "Error occured during whitelist report generation for %s" % (url)
    exit(1)


def add_wl_for_url(args):
  try:
    fh = open("/tmp/wl_report.wl", 'r')
    fstr = fh.read()
    fh.close()
    rule_str = None
    rules = []
    for section in re.finditer('#msg:.*\n#Rule.*\n#total.*\n(#peers.*\n)+#uri.*\n((#var_name\s:\s(.*)\n)*)\n(BasicRule\s\swl:(\d+).*?\|(.*?)(\|NAME)?");\n', fstr):
      rule_str = section.group(5)
      m=re.match('^(BasicRule\s\swl:\d+\s\")(.*)(\")$', rule_str)
      if m: 
	g2 = m.group(2).replace('"', '\\"')
	rule_str = m.group(1) + g2 + m.group(3)
      if section.group(4) != '':
	vars = section.group(2).rstrip().split('\n')
        for ivar in vars:
	  var = ''
	  if ivar != None:
	    v = re.match('^#var_name\s:\s(.*)$', ivar)
	    if v: var = v.group(1)
      	  rules.append({'id': section.group(6), 'var' : var, 'mz': section.group(7), 'rule_str': rule_str})
      else:
      	rules.append({'id': section.group(6), 'var' : section.group(4), 'mz': section.group(7), 'rule_str': rule_str})
    groups = {}
    for r in rules:
      var = r['var']
      key = var+r['mz']
      if key in groups.keys():
        groups[key]['ids'].append(r['id'])
      else:
        groups[key] = {'ids': [r['id']], 'rule_str': r['rule_str'], 'var' : var, 'mz' : r['mz']}
    fh = open(args.wl_rule, 'a')
    fstr = ""
    for g in groups.keys():
      sss = groups[g]['rule_str']
      if groups[g]['var'] != '':
      	sss = re.sub('\|(%s)'%(groups[g]['mz']), '|$\\1_VAR:%s'%(groups[g]['var']), sss)
      ret = re.sub('wl:\d+', 'wl:%s'%(",".join(groups[g]['ids'])), sss)
      fh.write(ret+';\n')
    fh.close()
  except Exception as e:
    print "Exception during wl line generation: %s" % (e.message)
    exit(1)


def generate_wl_file(args, urls):
  if len(urls) == 0:
    print "No whitelist file being generated."
    exit(0)
  if os.path.exists(args.wl_rule):
    os.remove(args.wl_rule)
  for url in urls:
    create_template_file(url)        	      # /tmp/temp.tpl
    generate_wl_report_for_url(args, url)     # use /tmp/temp.tpl, create /tmp/wl_url.wl
    print url
    add_wl_for_url(args)
  print "Whitelist file generated: %s" % (args.wl_rule)

def tag_event_by_wl_file(args):
  print "Tagging ES events. Please wait..."
  dates = args.idates
  cfg = args.cfg
  wl_rule = args.wl_rule
  server = "-s %s" % (args.server) if args.server != None else ""
  cmd = "python nxtool.py -c %s %s -w %s --tag  --idates=%s > /dev/null 2>&1" % (cfg, server, wl_rule, dates)
  res = os.system(cmd)
  if res >> 8 != 0:
    print "Error occured during ES events tagging"
    exit(1)
  print "All rule violation events are tagged in ES"

# Entry point
def main():
  #print str(datetime.now())
  args = get_options()
  gen_current_stat(args)
  urls = load_urls_from_stat()
  generate_wl_file(args, urls)
  tag_event_by_wl_file(args)
  #check_report()
  print "Done"
  #print str(datetime.now())

if __name__ == '__main__':
  main()

