#!/usr/bin/env python
# -*- coding: ascii -*-

"""
This module implements uses LokiBotPatcher class.

The input of this module is a LokiBot malware sample.

The control panels of that sample will be printed.
There is an option for rewriting those control panels with a
list of custom control panels.

Also, with this module, some bugs are fixed to all those LokiBot samples
which were patched before by 'Dimitry'

DISCLAIMER
Any actions and or activities related to the material contained within this script is solely your responsibility.
The misuse of the information in this script can result in criminal charges brought against the persons in question.
The author will not be held responsible in the event any criminal charges be brought against any individuals misusing the information in this script to break the law.
"""

__author__  = 'd00rt (@D00RT_RM)'
__email__   = 'd00rt.fake@gmail.com'
__date__    = '30-06-2018'
__version__ = '1.0'


import os
import sys
from lokibot import *


def check_arguments(patch, new_url, filename):
    if patch and not new_url:
        raise OptionValueError("-p param must be used with -u param.")
    if not patch and new_url:
        raise OptionValueError("-u param must be used with -p param.")
    if not filename and (new_url or patch):
        raise OptionValueError("-f param is mandatory.")


def get_parser():
    parser = OptionParser(usage="usage: %prog [options] lokibotfile",
                          version="%prog 1.0")

    parser.add_option("-p", "--patch",
                      action="store_true",
                      dest="patch",
                      default=False,
                      help="patch the lokibotfile with a new url. -u option is required")
    parser.add_option("-u", "--url",
                      action="store",
                      dest="urls",
                      default=None,
                      help="comma separated list of urls for patching lokibot control panels. -p option is required")
    parser.add_option("-f", "--file",
                      action="store",
                      dest="filename",
                      default=None,
                      help="file for patching. This param is MANDATORY")
    parser.add_option("-o", "--output",
                      action="store",
                      dest="o_filename",
                      default=None,
                      help="output file name for patched binary")

    return parser


def main(patch, urls, filename, o_filename):

    yarafile = os.path.join((os.path.dirname(os.path.realpath(__file__))), 'yara/lokibot.yar')

    try:
        lbp = LokiBotPatcher(filename, yarafile)
    except ExceptionItIsNotLokiBot as e:
        print str(e)
        exit(0)

    if lbp.PATCHED_VERSION:
        print "[+] LokiBot Hijacked version detected."
        print "\tControl panel: {u}".format(u=lbp.PATCHED_VERSION_CNC_URL)
    else:
        print "[+] LokiBot Hijacked version no detected."


    if lbp.CNC_URLS_3DES:
        print "[+] Original control panels:"
        for u in lbp.CNC_URLS_3DES:
            print "\t{u}".format(u=u)

        if patch and urls:
            patch_result = lbp.patch(urls)

            if patch_result == None:
                print "[!] LokiBot file could not be patched."
                print "\t[!] You inserted more urls than the MAX URL NUM accepted by this LokiBot sample"
                print "\t[!] The maximum url accepted by this sample is {l}. You inserted {lu} urls".format(l=lbp.MAX_CNC_URL_NUM, lu=len(urls))

            else:
                print "[+] LokiBot file patched."
                print "\tInput: {f}".format(f=filename)

                filename = filename + "_d00rt_patched.exe"
                if o_filename:
                    filename = o_filename

                lbp.dump(filename)
                print "\tOutput: {f}".format(f=filename)

                if patch_result:
                    print "\t[!] Some of the inserted urls are too long"
                    print "\t[!] The maximun length accepted for a url by this sample is {l}".format(l=lbp.MAX_CNC_URL_SIZE)
                    for u in patch_result:
                        print "\t\t[!] {u} length: {n}".format(u=u, n=len(u))

                print "[+] LokiBot new C&C urls."
                for u in lbp.CNC_URLS_3DES:
                    print "\t{u}".format(u=u)

    else:
        print "[+] Original control panels not found. "
            

if __name__ == '__main__':
    parser = get_parser()
    options, args = parser.parse_args()

    urls = []
    if options.urls:
        urls = options.urls.split(',')

    if not options.filename:
        parser.print_help()
        sys.exit(1)

    check_arguments(options.patch, urls, options.filename)
    main(options.patch, urls, options.filename, options.o_filename)
