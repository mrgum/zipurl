#!/usr/bin/env python3

from struct import *
import os
import requests
import sys
import re

import pprint

class zipurl(object):
    ##
    grab_size = 286 ## enough to get the 30 byte header and a 255 long filename - may not get whole header
    
    pp = pprint.PrettyPrinter(indent=2)
    
    recordformat = dict()
    '''
    Local file header
    Offset  Bytes   Description[23]
    0   4   Local file header signature = 0x04034b50 (read as a little-endian number)
    4   2   Version needed to extract (minimum)
    6   2   General purpose bit flag
    8   2   Compression method
    10  2   File last modification time
    12  2   File last modification date
    14  4   CRC-32
    18  4   Compressed size
    22  4   Uncompressed size
    26  2   File name length (n)
    28  2   Extra field length (m)
    30  n   File name
    30+n    m   Extra field
    '''
    zip_local_file_header_length = 30
    recordformat['zlfh'] = [
        ('header', '4'), ## 4 byte 'PK..' Local file header signature = 0x04034b50 (read as a little-endian number)
        ('minVersion', '2'),
        ('generalPurpose', '2'),
        ('compressionMethod', '2'),
        ('lastModTime', '2'),
        ('lastModDate', '2'),
        ('crc32', '4'),
        ('sizeCompressed', '4'),
        ('sizeUncompressed', '4'),
        ('filenameLength', '2'),
        ('extraFieldLength', '2'),
        ('fileName', 'filenameLength'),
        ('extraField', 'extraFieldLength'),
    ]
    
    
    #### debugging functions
    def hexprint(self, r):
        print("".join("\\x%02x" % i for i in r))
    
    
    def hex_to_int(self, h, extra=''):
        res = int.from_bytes(h, byteorder='little')
        #if extra == '':
        #    print('hex_to_int {}: {} -> {}: {}'.format(type(h), h, type(res), res))
        #else:
        #    print('hex_to_int {} {}: {} -> {}: {}'.format(extra, type(h), h, type(res), res))
        return res
    
    ## TODO provide generic read_record that uses the appropriate method for the type of argument
    def read_record_from_file(self, format, file):
        rec = dict()
        if format not in self.recordformat:
            print('unknown record format {}'.format(format))
            return
        for f in self.recordformat[format]:
            fn = f[0] # field name
            fl = f[1] # field length
            #print('reading {} as {}'.format(fn, fl))
            if fl.isdigit():
                rec[fn] = file.read(int(fl))
            else:
                rec[fn] = file.read(self.hex_to_int(rec[fl]), fn)
                #print('read {} from {} bytes {}'.format(fn, hex_to_int(rec[fl]), rec[fl]))
        return rec
    
    def read_record_from_content(self, format, content):
        rec = dict()
        if format not in self.recordformat:
            print('unknown record format {}'.format(format))
            return
        offset = 0
        for f in self.recordformat[format]:
            fn = f[0] # field name
            fl = f[1] # field length
            if fl.isdigit():
                end = offset + int(fl)
            else:
                end = offset + self.hex_to_int(rec[fl], fl)
            rec[fn] = content[offset:end]
            if format == 'zlfh' and fn == 'header' and rec[fn] != b'PK\x03\x04': ## abort early
                print('record does not look like a {}'.format(format))
                return None
            #print('read {} as {} got {}'.format(fn, fl, rec[fn]))
            offset = end
        return rec
    
    '''
    Central directory file header Offset    Bytes   Description[23]
    0   4   Central directory file header signature = 0x02014b50
    4   2   Version made by
    6   2   Version needed to extract (minimum)
    8   2   General purpose bit flag
    10  2   Compression method
    12  2   File last modification time
    14  2   File last modification date
    16  4   CRC-32
    20  4   Compressed size
    24  4   Uncompressed size
    28  2   File name length (n)
    30  2   Extra field length (m)
    32  2   File comment length (k)
    34  2   Disk number where file starts
    36  2   Internal file attributes
    38  4   External file attributes
    42  4   Relative offset of local file header. This is the number of bytes between the start of the first disk on which the file occurs, and the start of the local file header. This allows software reading the central directory to locate the position of the file inside the .ZIP file.
    46  n   File name
    46+n    m   Extra field
    46+n+m  k   File comment
    '''
    def cd_record(self, zfr):
        cdr = b'PK\x01\x02' # signature
        cdr += pack('<h', 0)      ## version that created
        cdr += zfr['minVersion']
        cdr += zfr['generalPurpose']
        cdr += zfr['compressionMethod']
        cdr += zfr['lastModTime']
        cdr += zfr['lastModDate']
        cdr += zfr['crc32']
        cdr += zfr['sizeCompressed']
        cdr += zfr['sizeUncompressed']
        cdr += zfr['filenameLength']
        cdr += zfr['extraFieldLength']
        cdr += pack('<h', 0)   ## no comment
        cdr += pack('<h', 0)   ## always disk 0
        cdr += pack('<h', 0)   ## Internal file attributes
        cdr += pack('<l', 0)   ## External file attributes
        cdr += pack('<l', 0)   ## Relative offset of local file header. (its at the start as only one file)
        cdr += zfr['fileName']
        cdr += zfr['extraField']
        return cdr
    
    '''
    End of central directory record (EOCD) Offset   Bytes   Description[23]
    0   4   End of central directory signature = 0x06054b50
    4   2   Number of this disk
    6   2   Disk where central directory starts
    8   2   Number of central directory records on this disk
    10  2   Total number of central directory records
    12  4   Size of central directory (bytes)
    16  4   Offset of start of central directory, relative to start of archive
    20  2   Comment length (n)
    22  n   Comment
    
    the only thing we need is the length of the record as this will be the byte offset of the central directory record
    '''
    def eocd_record(self, zfr):
        eocdr = b'PK\x05\x06' # signature
        eocdr += pack('<h', 0) # Number of this disk
        eocdr += pack('<h', 0) # Disk where central directory starts
        eocdr += pack('<h', 1) # Number of central directory records on this disk
        eocdr += pack('<h', 1) # Total number of central directory records
        sizeCD = self.hex_to_int(zfr['filenameLength']) + 46  # Size of central directory (bytes) [46 + filename]
        eocdr += pack('<l', sizeCD)
        eocdr += pack('<I', zfr['recordLength']) # Offset of start of central directory, relative to start of archive [after our first and only record]
        eocdr += pack('<h', 0) # Comment length (n)
        return eocdr
    
    ## grab a bit of a file and save it
    ## zfr is a zip_file_record
    def fetch_file(self, zfr, directory):
    
        filename = '{}/{}.zip'.format(directory, os.path.basename(zfr['fileName'].decode('utf-8')))
        print('creating new zipfile {}'.format(filename))
        ## this is the zip record which includes the data
        headers = {'Range': 'bytes={}-{}'.format(zfr['byteStart'], zfr['byteStart'] + zfr['recordLength'] - 1)}
        r = requests.get(zfr['url'], headers=headers, stream=True)
        with open(filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk: # filter out keep-alive new chunks
                    f.write(chunk)
            ## we write a cd record
            #print('getting a cd file record')
            cdr = self.cd_record(zfr)
            #pp.pprint(cdr)
            f.write(cdr)
            ## we write a eocd record
            #print('getting a eocd record')
            eocd = self.eocd_record(zfr)
            #pp.pprint(eocd)
            f.write(eocd)
        print('wrote out new zipfile {}'.format(filename))
    
    ## we could get the 30 byte zip header plus 256 bytes (longest filename we expect) but then we'd have the complezity of what to do if thise grab_size bytes contained some of the next record
    ## lets do that and not care about fetching the same data over and over
    def get_zipurl_index(self, url, bytestart = 0, bytelength = None):
        if bytelength is None:
            bytelength = self.grab_size
        headers = {'Range': 'bytes={}-{}'.format(bytestart, bytestart + bytelength)}
        r = requests.get(url, headers=headers)
        zip_file_record = self.read_record_from_content('zlfh', r.content)
        if zip_file_record is None:
            return None
        print("title is {}".format(zip_file_record['fileName']))
        recordLength = self.zip_local_file_header_length + self.hex_to_int(zip_file_record['filenameLength']) + self.hex_to_int(zip_file_record['sizeCompressed']) + self.hex_to_int(zip_file_record['extraFieldLength'])
        zip_file_record['recordLength'] = recordLength
        self.get_zipurl_index(url, bytestart + zip_file_record['recordLength'], bytelength)
    
    ## by getting the whole record we get a string we could use as a zipfile but might need to add a central directory to the end
    def get_zipurl_files(self, url, pattern, directory, bytestart = 0, bytelength = None):
        if bytelength is None:
            bytelength = self.grab_size
        headers = {'Range': 'bytes={}-{}'.format(bytestart, bytestart + bytelength)}
        r = requests.get(url, headers=headers)
        zip_file_record = self.read_record_from_content('zlfh' ,r.content)
        if zip_file_record is None:
            return None
        print('title is {}'.format(zip_file_record['fileName']))
        recordLength = self.zip_local_file_header_length + self.hex_to_int(zip_file_record['filenameLength']) + self.hex_to_int(zip_file_record['sizeCompressed']) + self.hex_to_int(zip_file_record['extraFieldLength'])
        zip_file_record['recordLength'] = recordLength
        if pattern.search(zip_file_record['fileName'].decode('utf-8')):
            print('found a file we want {}'.format(zip_file_record['fileName']))
            #pp.pprint(zip_file_record)
            ## need to either create the central directory entry or read that first
            zip_file_record['byteStart'] = bytestart
            zip_file_record['url'] = url
            self.fetch_file(zip_file_record, directory)
    
        self.get_zipurl_files(url, pattern, directory, bytestart + recordLength, bytelength)
    
    ## TODO: use argparser or something similar and provide usage help
    def main(self):
        operation = sys.argv[1]
        url = sys.argv[2] ## e.g. "http://patents.reedtech.com/downloads/pairdownload/12501057.zip"
        if operation == 'list':
            self.get_zipurl_index(url)
        elif operation == 'get':
            pattern = sys.argv[3]
            pattern = re.compile(sys.argv[3]) ## e.g. '-FWCLM.pdf|-transaction_history.tsv$'
            directory = sys.argv[4] # e.g. 'zip'
            self.get_zipurl_files(url, pattern, directory)
        else:
            print('operation {} not recognised'.format(operation))
    
if __name__ == "__main__":
    zipurl().main()
