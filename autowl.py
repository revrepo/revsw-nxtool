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
  

def create_template_file():
  try:
    fh = open('/tmp/temp.tpl', 'w')
    fstr = """{
   "_msg" : "auto_gen_temp_file",
   "uri"  : "?",
   "zone" : "?",
   "id"   : "?"
}"""
    fh.write(fstr)
    fh.close()
  except Exception as e:
    print "Exception during template file creation : %s" % e.message
    exit(1)

def generate_wl_report(args):
  dates = args.idates
  cfg = args.cfg
  server = "-s %s" % (args.server) if args.server != None else ""
  cmd = 'python nxtool.py -c %s %s -t /tmp/temp.tpl --slack --idates=%s --colors > /tmp/wl_report.wl' % (cfg, server, dates)
  res = os.system(cmd)
  if res >> 8 != 0:
    print "Error occured during whitelist report generation"
    exit(1)


def dump_wl_file(args):
  try:
    fh = open("/tmp/wl_report.wl", 'r')
    fstr = fh.read()
    fh.close()
    if re.search('\n0 whitelists', fstr) == None:
    	if os.path.exists(args.wl_rule):
    	  os.remove(args.wl_rule)
    else:
    	print 'No rule violation found.'
    	return False
    rule_str = None
    rules = {}
    for section in re.finditer('#msg:.*\n#Rule.*\n#total.*\n(#peers.*\n)+#uri\s:\s(.*)\n((#var_name\s:\s(.*)\n)*)\n(BasicRule\s\swl:(\d+).*?\|(.*?)(\|NAME)?");\n', fstr):
      rule_str = section.group(6)
      m=re.match('^(BasicRule\s\swl:\d+\s\")(.*)(\")$', rule_str)
      if m: 
	g2 = m.group(2).replace('"', '\\"')
	rule_str = m.group(1) + g2 + m.group(3)
      uri = section.group(2)
      mz = section.group(8)
      nz = section.group(9) if section.group(9) != None else ''
      id = section.group(7)
      varss = []
      if section.group(5) != '':
	vars = section.group(3).rstrip().split('\n')
        for ivar in vars:
	  var = ''
	  if ivar != None:
	    v = re.match('^#var_name\s:\s(.*)$', ivar)
	    if v: var = v.group(1)
	    if uri in rules.keys():
		rules[uri].append({'id' : id, 'mz' : mz, 'rule_str' : rule_str, 'var' : var, 'nz' : nz}) 
	    else:
		rules[uri] = [{'id' : id, 'mz' : mz, 'rule_str' : rule_str, 'var' : var, 'nz' : nz}]
      else:
	    if uri in rules.keys():
		rules[uri].append({'id' : id, 'mz' : mz, 'rule_str' : rule_str, 'var' : '', 'nz' : nz}) 
	    else:
		rules[uri] = [{'id' : id, 'mz' : mz, 'rule_str' : rule_str, 'var' : '', 'nz' : nz}]
    for uri in rules.keys():
      groups = {}
      for r in rules[uri]:
        var = r['var']
        key = var+r['mz']+r['nz']
        if key in groups.keys():
          groups[key]['ids'].append(r['id'])
        else:
          groups[key] = {'ids': [r['id']], 'rule_str': r['rule_str'], 'var' : var, 'mz' : r['mz'], 'nz' : r['nz']}
      fh = open(args.wl_rule, 'a')
      fstr = ""
      for g in groups.keys():
        sss = groups[g]['rule_str']
        if groups[g]['var'] != '':
        	sss = re.sub('\|(%s)'%(groups[g]['mz']), '|$\\1_VAR:%s'%(groups[g]['var']), sss)
        ret = re.sub('wl:\d+', 'wl:%s'%(",".join(groups[g]['ids'])), sss)
        fh.write(ret+';\n')
      fh.close()
    return True
  except Exception as e:
    print "Exception during wl line generation: %s" % (e.message)
    exit(1)


def generate_wl_file(args):
  create_template_file()       # /tmp/temp.tpl
  generate_wl_report(args)     # use /tmp/temp.tpl
  b=dump_wl_file(args)
  if b: print "Whitelist file generated: %s" % (args.wl_rule)
  return b

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
  b=generate_wl_file(args)
  if b: 
  	#print str(datetime.now())
  	#tag_event_by_wl_file(args)
	True
  print "Done"
  #print str(datetime.now())

if __name__ == '__main__':
  main()

