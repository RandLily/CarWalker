#按需增减搜索项，缩小目标范围
#bannedfunctions=(strcpy strcat strncat sprintf vsprintf strlen memcpy memcmp memset fopen gets getwd scanf)
#binaries=(ssh sshd scp sftp tftp busybox telnet telnetd openssl ftpget ftpput)
#cmdinjects=(system exec execl popen execve ShellExecute os.execute os.system subprocess.call eval cmd)
dbfiles=(*.db *.sqlite *.sqlite3 *.sqlitedb *.store *.sql)
files=(*.conf *.cfg *.ini *.bak *.mp4)
passfiles=(passwd shadow *.psk *.key *.lisence)
patterns=(admin root password passwd pwd ssl ssh key telnet secret pgp gpg token api auth 密)
sshfiles=(*authorized_keys* *host_key* *id_rsa* *id_dsa* *.pub)
sslfiles=(*.crt *.pem *.cer *.p7b *.p12 *.key)
#可选*.asp *.html *.xml *.php *.js *.json *.jsp 等
webfiles=(*.cgi)
webservers=(*web apache alphapd *httpd GoAhead nginx Boa)

function usage {
        echo "Usage:"
        echo "$0 {path to extracted file system of firmware}\
 {optional: name of the file to store results - defaults to carwalker.txt}"
    echo "Example: ./$0 linksys/fmk/rootfs/"
        exit 1
}

function msg {
    echo "$1" | tee -a $FILE
}

# Check for arguments
if [[ $# -gt 2 || $# -lt 1 ]]; then
    usage
fi

# Set variables
FIRMDIR=$1
if [[ $# -eq 2 ]]; then
    FILE=$2
else
    FILE="carwalker.txt"
fi

# Remove previous file if it exists, is a file and doesn't point somewhere
if [[ -e "$FILE" && ! -h "$FILE" && -f "$FILE" ]]; then
    rm -f $FILE
fi

# cut number
CUTNUM=${#FIRMDIR}
CUTNUM=$(($CUTNUM+1))

# Perform searches
msg "***Firmware Directory***"
msg $FIRMDIR


msg "***Search for password files(FileName contain eg: passwd、shadow...)***"
for passfile  in "${passfiles[@]}"
do
    msg "##################################### $passfile"
    find $FIRMDIR -iname $passfile | cut -c${CUTNUM}- | tee -a $FILE
    msg ""
done


msg "***Search for Unix-MD5 hashes***"
egrep -sro '\$1\$\w{8}\S{23}' $FIRMDIR | tee -a $FILE


msg ""
if [[ -d "$FIRMDIR/etc/ssl" ]]; then
    msg "***List etc/ssl directory***"
    ls -l $FIRMDIR/etc/ssl | tee -a $FILE
fi
msg ""


msg "***Search for SSL related files(FileName contain eg: *.crt *pem...)***"
for sslfile in ${sslfiles[@]}
do
    msg "##################################### $sslfile"
    find $FIRMDIR -iname $sslfile | cut -c${CUTNUM}- | tee -a $FILE
       certfiles=( $(find ${FIRMDIR} -iname ${sslfile}) )
       : "${certfiles:=empty}"
    msg ""
done


msg ""
msg "***Search for SSH related files(FileName contain eg: authorized_keys *id_rsa* *.pub...)***"
for sshfile in ${sshfiles[@]}
do
    msg "##################################### $sshfile"
    find $FIRMDIR -iname $sshfile | cut -c${CUTNUM}- | tee -a $FILE
    msg ""
done


msg ""
msg "***Search for config files(FileName contain eg: *conf *ini...)***"
for file in ${files[@]}
do
    msg "##################################### $file"
    find $FIRMDIR -iname $file | cut -c${CUTNUM}- | tee -a $FILE
    msg ""
done


msg ""
msg "***Search for database related files(FileName contain eg: *.db *.sql...)***"
for dbfile in ${dbfiles[@]}
do
    msg "##################################### $dbfile"
    find $FIRMDIR -iname $dbfile | cut -c${CUTNUM}- | tee -a $FILE
    msg ""
done


msg ""
msg "***Search for shell scripts(FileName contain eg: *.sh...)***"
msg "##################################### shell scripts"
find $FIRMDIR -iname "*.sh" | cut -c${CUTNUM}- | tee -a $FILE


msg ""
msg "***Search for .bin files(FileName contain eg: *.bin...)***"
msg "##################################### bin files"
find $FIRMDIR -iname "*.bin" | cut -c${CUTNUM}- | tee -a $FILE


msg ""
msg "***Search for sensitive in files content(FileContent contain eg: upgrade admin password...)***"
for pattern in "${patterns[@]}"
do
    msg "-------------------- $pattern --------------------"
    grep -sirnow $FIRMDIR -e "$pattern" --exclude=*.jpg --exclude=*.png --exclude=*.gif --exclude=*.css | cut -c${CUTNUM}- | tee -a $FILE
    msg ""
done


msg ""
msg "***Search for web servers(FileName contain eg: apache nginx httpd...)***"
msg "##################################### search for web servers"
for webserver in ${webservers[@]}
do
    msg "##################################### $webserver"
    find $FIRMDIR -iname "$webserver" | cut -c${CUTNUM}- | tee -a $FILE
    msg ""
done


msg "***Search for command injection functions(FileContent contain method eg: system exec eval cmd...)***"
msg "##################################### Command injection functions"
for cmdinject in ${cmdinjects[@]}
do
    msg "##################################### $cmdinject"
    grep -sirnow $FIRMDIR -e "$cmdinject" | sort | uniq | cut -c${CUTNUM}- | tee -a $FILE
    msg ""
done


msg "***Search for banned C functions(FileContent contain method eg: strcpy strcat gets scanf...)***"
#https://github.com/intel/safestringlib/wiki/SDL-List-of-Banned-Functions
msg "##################################### Banned C functions"
for bannedfunction in "${bannedfunctions[@]}"
do
        msg "##################################### $bannedfunctions"
        grep -sirnow $FIRMDIR -e "$bannedfunction" | sort | uniq | cut -c${CUTNUM}- | tee -a $FILE
        msg ""
done


msg ""
msg "***Search for important binaries(FileName contain eg: ssh telnet sftp busybox...)***"
msg "##################################### important binaries"
for binary in "${binaries[@]}"
do
    msg "##################################### $binary"
    find $FIRMDIR -iname "$binary" | cut -c${CUTNUM}- | tee -a $FILE
    msg ""
done


msg ""
msg "***Search for webfiles(FileName contain eg: *asp *.html *.js...)***"
msg "##################################### webfiles"
for webfile in "${webfiles[@]}"
do
    msg "##################################### $webfiles"
    find $FIRMDIR -iname "$webfile" | cut -c${CUTNUM}- | tee -a $FILE
    msg ""
done


msg ""
msg "***Search for ip addresses***"
msg "##################################### ip addresses"
#grep -sRIEo '\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' --exclude=*.jpg --exclude=*.png --exclude=*.gif --exclude=*.css $FIRMDIR | sort | uniq | tee -a $FILE


msg ""
msg "***Search for urls***"
msg "##################################### urls"
#grep -sRIEo '(http|https|ws|mqtt|mqtts|ftp|ftps|sftp|coap)://[^/"]+' --exclude=*.jpg --exclude=*.png --exclude=*.gif --exclude=*.css $FIRMDIR | sort | uniq | tee -a $FILE


msg ""
msg "***Search for emails***"
msg "##################################### emails"
#grep -sRIEo '[A-Za-z0-9]+@[A-Za-z0-9]+(\.[A-Za-z0-9]+){1,2}' "$@" --exclude=*.jpg --exclude=*.png --exclude=*.gif --exclude=*.css $FIRMDIR | sort | uniq | tee -a $FILE


msg ""
msg "***Search for phonenumbers***"
msg "##################################### phonenumbers"
#grep默认使用BRE，grep -E使用ERE，grep -P使用PCRE
#^1[3-9]\d{9}$
grep -sRIEo '1((34[0-8])|(8[0-9]{2})|(([35][0-35-9]|4[579]|66|7[35678]|9[1389])[0-9]))[0-9]{7}' "$@" --exclude=*.jpg --exclude=*.js --exclude=*.json --exclude=*.png --exclude=*.gif --exclude=*.html --exclude=*.conf --exclude=*.cfg --exclude=*.bin --exclude=*.xml --exclude=*.bin --exclude=*.css $FIRMDIR | sort | uniq | tee -a $FILE


msg ""
msg "***Search for IDnumbers***"
msg "##################################### IDnumbers"
#15位身份证号正则：
#([1-6][1-9]|50)\d{4}\d{2}((0[1-9])|10|11|12)(([0-2][1-9])|10|20|30|31)\d{3}$
grep -sRIEo '([1-6][1-9]|50)[0-9]{4}(18|19|20)[0-9]{2}((0[1-9])|10|11|12)(([0-2][1-9])|10|20|30|31)[0-9]{3}[0-9Xx]$' "$@" --exclude=*.jpg --exclude=*.png --exclude=*.gif --exclude=*.css $FIRMDIR | sort | uniq | tee -a $FILE


msg ""
msg "***Search for carinfo***"
msg "##################################### vin"
#字母I、O和Q不能使用,第一位限定L只针对国产车
grep -sRIEo 'L[0-9A-HJ-NPR-Z]{7}[0-9X][0-9A-HJ-NPR-Z]{8}' "$@" --exclude=*.jpg --exclude=*.png --exclude=*.gif --exclude=*.css $FIRMDIR | sort | uniq | tee -a $FILE


msg ""
msg "##################################### carnumber"
#民用车牌、新能源车牌
grep -sRIEo '([京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z](([0-9]{5}[DF])|(DF[0-9]{4})))|([京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领][A-Z][A-HJ-NP-Z0-9]{4}[A-HJ-NP-Z0-9挂学警港澳])$' "$@" $FIRMDIR | sort | uniq | tee -a $FILE


msg ""
msg "##################################### longtitude"
grep -sRIEo '[2345][0-9]\.[0-9]{2,10}' "$@" --exclude=*.jpg --exclude=*.js --exclude=*.json --exclude=*.png --exclude=*.gif --exclude=*.html --exclude=*.conf --exclude=*.xml --exclude=*.bin --exclude=*.css $FIRMDIR | sort | uniq | tee -a $FILE
