#!/bin/bash
PORT=$((RANDOM%64025+1024))
PORTEND=$((${PORT} + 1500))
S=`date +%s`
OK=`echo -e "[ \e[0;32mDONE\e[00m ]"`
genpass=`perl -le 'print map {(a..z,A..Z,0..9)[rand 62] } 0..pop' 15`
HTPASSWD="/etc/apache2/htpasswd"
rutorrent="/srv/rutorrent/"
REALM="rutorrent"
IRSSI_PASS=`perl -le 'print map {(a..z,A..Z,0..9)[rand 62] } 0..pop' 15`
IRSSI_PORT=$((RANDOM%64025+1024))
P=$((RANDOM%64025+1024))
ip=`/sbin/ifconfig | grep "inet addr" | awk -F: '{print $2}' | awk '{print $1}'|grep -v "^127"|head -n1`


function _intro() {
if [[ $EUID -ne 0 ]];then
    echo "rTorrent Installer: User has to be root"
    exit 1
fi
echo "Do not hit any keys during the install, they keys you press before you are"
echo "required to, it will/can be used as the username. So wait for the username"
echo "promt before you hit any keys"
echo ""
echo ""
echo "Press ENTER when you're ready to begin ... "
read input
echo "This can take awhile depending on your servers hardware specs ... "
}

function _update() {
ver=`lsb_release -c|awk '{print $2}'`
echo -n "Updating system ... "
wget -q http://www.deb-multimedia.org/pool/main/d/deb-multimedia-keyring/deb-multimedia-keyring_2012.05.05_all.deb -O deb-multimedia-keyring.deb>/dev/null 2>&1
dpkg -i deb-multimedia-keyring_all.deb >/dev/null 2>&1
rm -rf deb-multimedia-keyring_all.deb>/dev/null 2>&1

cat >/etc/apt/sources.list<<EOF
deb http://ftp.nl.debian.org/debian stable main contrib non-free
deb-src http://ftp.nl.debian.org/debian stable main contrib non-free
deb http://ftp.debian.org/debian/ ${ver}-updates main contrib non-free
deb-src http://ftp.debian.org/debian/ ${ver}-updates main contrib non-free
deb http://security.debian.org/ ${ver}/updates main contrib non-free
deb-src http://security.debian.org/ ${ver}/updates main contrib non-free
deb http://www.deb-multimedia.org wheezy main non-free
deb http://packages.dotdeb.org wheezy all
deb-src http://packages.dotdeb.org wheezy all
EOF
wget http://www.dotdeb.org/dotdeb.gpg
apt-key add dotdeb.gpg
apt-get update>/dev/null 2>&1
apt-get -y purge samba samba-common>/dev/null 2>&1
apt-get -y upgrade>/dev/null 2>&1
echo ${OK}
}

function _depends() {
echo -n "Installing: nano, bwm-ng, ifstat, rtorrent, libtorrent, rar, mediainfo and irssi-autodl perl modules ... "
APT=`apt-get install -qq --force-yes -y bc sudo screen zip irssi unzip nano build-essential bwm-ng ifstat git subversion \
	automake libtool libcppunit-dev libssl-dev pkg-config libcurl4-openssl-dev libsigc++-2.0-dev \
	unzip unrar curl libncurses5-dev yasm apache2 php5 php5-cli \
	fontconfig libfontconfig1 libfontconfig1-dev rar unrar mediainfo php5-curl \
	ttf-mscorefonts-installer libarchive-zip-perl libnet-ssleay-perl php5-geoip \
	libhtml-parser-perl libxml-libxml-perl libjson-perl libjson-xs-perl libxml-libxslt-perl libapache2-mod-scgi >/dev/null 2>&1`
wget -q http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz>/dev/null 2>&1
gunzip GeoLiteCity.dat.gz>/dev/null 2>&1
mkdir -p /usr/share/GeoIP>/dev/null 2>&1
mv GeoLiteCity.dat /usr/share/GeoIP/GeoIPCity.dat>/dev/null 2>&1
(echo y;echo o conf prerequisites_policy follow;echo o conf commit)|cpan Digest::SHA1 >/dev/null 2>&1
(echo y;echo o conf prerequisites_policy follow;echo o conf commit)|cpan Digest::SHA >/dev/null 2>&1
echo ${OK}
}

function _askffmpeg() {
echo -n "Install ffmpeg (Used for screenshots) (Y/n): "
read responce
case $responce in
        [yY] | [yY][Ee][Ss] | "" )
ffmpeg=yes
	;;
	[nN] | [nN][Oo] )
ffmpeg=no
	;;
esac
}

function _ffmpeg() {
if [[ ${ffmpeg} == "yes" ]]; then
echo -n "Building ffmpeg form source for screenshots ... "
cd /tmp
git clone git://source.ffmpeg.org/ffmpeg.git ffmpeg >/dev/null 2>&1
cd ffmpeg
export FC_CONFIG_DIR=/etc/fonts
export FC_CONFIG_FILE=/etc/fonts/fonts.conf
./configure --enable-libfreetype --enable-filter=drawtext --enable-fontconfig >/dev/null 2>&1
make >/dev/null 2>&1
make install >/dev/null 2>&1
cp /usr/local/bin/ffmpeg /usr/bin >/dev/null 2>&1
cp /usr/local/bin/ffprobe /usr/bin >/dev/null 2>&1
rm -rf /tmp/ffmpeg >/dev/null 2>&1
echo ${OK}
fi
}

function _xmlrpc() {
echo -n "Building xmlrpc-c from source ... "
cd /tmp
svn -q checkout http://svn.code.sf.net/p/xmlrpc-c/code/stable/ xmlrpc-c
cd xmlrpc-c
./configure --prefix=/usr --disable-cplusplus >/dev/null 2>&1
make >/dev/null 2>&1
make install >/dev/null 2>&1
echo ${OK}
}

function _libtorrent() {
echo -n "Building libtorrent-0.13.4 from source ... "
cd /tmp
rm -rf xmlrpc-c  >/dev/null 2>&1
wget -q http://libtorrent.rakshasa.no/downloads/libtorrent-0.13.4.tar.gz
tar -xzvf libtorrent-0.13.4.tar.gz >/dev/null 2>&1
cd libtorrent-0.13.4
./autogen.sh >/dev/null 2>&1
./configure --prefix=/usr >/dev/null 2>&1
make >/dev/null 2>&1
make install >/dev/null 2>&1
echo ${OK}
}

function _rtorrent() { 
echo -n "Building rtorrent-0.9.4 from source ... "
cd /tmp
rm -rf libtorrent-0.13.4* >/dev/null 2>&1
wget -q http://libtorrent.rakshasa.no/downloads/rtorrent-0.9.4.tar.gz
tar -xzvf rtorrent-0.9.4.tar.gz >/dev/null 2>&1
cd rtorrent-0.9.4
./configure --prefix=/usr --with-xmlrpc-c >/dev/null 2>&1
make >/dev/null 2>&1
make install >/dev/null 2>&1
cd /tmp
ldconfig >/dev/null 2>&1
rm -rf /tmp/rtorrent-0.9.4* >/dev/null 2>&1
echo ${OK}
}

function _scgi() { ln -s /etc/apache2/mods-available/scgi.load /etc/apache2/mods-enabled/scgi.load >/dev/null 2>&1 ; }

function _apacheconf() {
echo -n "Setting up seedbox.conf for apache ... "
a2enmod auth_digest >/dev/null 2>&1
a2enmod ssl >/dev/null 2>&1
a2enmod scgi >/dev/null 2>&1
a2enmod rewrite >/dev/null 2>&1
mv /etc/apache2/sites-enabled/000-default /etc/apache2/ >/dev/null 2>&1
cat >/etc/apache2/sites-enabled/default-ssl<<EOF
SSLPassPhraseDialog  builtin
SSLSessionCache         shmcb:/var/cache/mod_ssl/scache(512000)
SSLSessionCacheTimeout  300
SSLMutex default
SSLRandomSeed startup file:/dev/urandom  256
SSLRandomSeed connect builtin
SSLCryptoDevice builtin
<VirtualHost *:80>
    ServerAdmin lamer@lamer.com
    ServerName ${ip}
    Redirect permanent / https://${ip}
    RedirectMatch ^/(.*)$ https://%{SERVER_NAME}/$1
    RewriteEngine on
    RewriteCond %{SERVER_PORT} !^443$
    RewriteRule ^.*$ https://%{SERVER_NAME}%{REQUEST_URI} [L,R]    
</VirtualHost>
<VirtualHost ${ip}:443>
SSLEngine on
        DocumentRoot "/srv/rutorrent/"
        <Directory "/srv/rutorrent/">
                Options Indexes FollowSymLinks
                AllowOverride All AuthConfig
                Order allow,deny
                Allow from all
        AuthType Digest
        AuthName "${REALM}"
        AuthUserFile '${HTPASSWD}'
        Require valid-user
        </Directory>
        SSLEngine on
        SSLProtocol all -SSLv2
        SSLCipherSuite ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW
        SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
        SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
        SetEnvIf User-Agent ".*MSIE.*" \
                 nokeepalive ssl-unclean-shutdown \
                 downgrade-1.0 force-response-1.0
                 SCGIMount /RPC2 127.0.0.1:$P
</VirtualHost>
EOF
echo ${OK}
}

function _rutorrent() {
echo -n "Installing rutorrent into /srv ... "
cd /srv
svn -q co http://rutorrent.googlecode.com/svn/trunk/rutorrent
echo ${OK}
}

function _adduser() {
echo -n "Username: "
read username
useradd ${username} -m -G www-data
echo -n "Password: (hit enter to generate a password) "
read password
if [[ ! -z "${password}" ]]; then
        echo "setting password to ${password}"
        passwd=${password}
        echo "${username}:${passwd}" | chpasswd >/dev/null 2>&1
        (echo -n "${username}:${REALM}:" && echo -n "${username}:${REALM}:${passwd}" | md5sum | awk '{print $1}' ) >> ${HTPASSWD}
else
        echo "setting password to ${genpass}"
        passwd=${genpass}
        echo "${username}:${passwd}" | chpasswd >/dev/null 2>&1
        (echo -n "${username}:${REALM}:" && echo -n "${username}:${REALM}:${passwd}" | md5sum | awk '{print $1}' ) >> ${HTPASSWD}
fi
}

function _rconf() {
echo -n "Installing .rtorrent.rc for ${username} ... "
cat >/home/${username}/.rtorrent.rc<<EOF
#scgi_local = /home/${username}/.rtorrent.rpc
scgi_port = localhost:$P
min_peers = 50
max_peers = 200
min_peers_seed = 10
max_peers_seed = 50
max_uploads = 15
download_rate = 0
upload_rate = 0
directory = /home/${username}/torrents/
session = /home/${username}/.sessions/
schedule = watch_directory,5,5,load_start=/home/${username}/watch/*.torrent
schedule = low_diskspace,5,60,close_low_diskspace=200M
port_range = ${PORT}-${PORTEND}
check_hash = no
use_udp_trackers = yes
encryption = allow_incoming,enable_retry,prefer_plaintext
dht = off
peer_exchange = no
ratio.enable=
ratio.min.set=490
ratio.max.set=501
ratio.upload.set=600M
schedule = chmod,0,0,"execute=chmod,777,/home/${username}/.rtorrent.rpc"
#system.method.set = group.seeding.ratio.command, d.close=, d.erase=,"execute={rm,-rf,--,\$d.get_base_path=}"
#system.method.set_key = event.download.erased, remove_file,"execute={rm,-drf,--,\$d.get_base_path=}"
EOF
echo ${OK}
}

function _plugins() {
echo -n "Installing plugins ... "
cd ${rutorrent}plugins
for i in cpuload data diskspace erasedata rpc seedingtime theme datadir tracklabels trafic unpack _getdir rssurlrewrite; do
svn -q co http://rutorrent.googlecode.com/svn/trunk/plugins/$i
done
svn -q co http://svn.rutorrent.org/svn/filemanager/trunk/fileshare
svn -q co http://rutorrent-logoff.googlecode.com/svn/trunk/ logoff
svn -q co https://github.com/zebraxxl/rutorrentMobile >/dev/null
#svn -q co https://svn.code.sf.net/p/autodl-irssi/code/trunk/rutorrent/autodl-irssi
git clone https://github.com/autodl-community/autodl-rutorrent.git autodl-irssi >/dev/null 2>&1
svn -q co http://svn.rutorrent.org/svn/filemanager/trunk/filemanager >/dev/null 2>&1

cat >${rutorrent}/plugins/filemanager/scripts/screens<<'DUR'
#!/bin/bash
if [ ! -d "$2" ]; then
mkdir --mode=0777 -p "$2" || { echo "FATAL ERROR: temp dir creation failed"; exit; }
fi
echo "$$" > "$2/pid";
if [ ! -w "${4%/*}" ]; then
echo "1: FATAL ERROR: Destination ${4%/*} not permitted" >> "$2/log"; 
else
START=$(date +%s.%N)
"$1" -i "$3" -an -vf drawtext="timecode='00\:00\:00\:00' :rate=24 :fontcolor=white :fontsize=21 :shadowcolor=black :x=5 :y=5",scale="min($6\, iw*3/2):-1",select="not(mod(n\,$5)),tile=$8x$7" -vsync 0 -frames:v 1 "$4" 2>&1 | sed -u 's/^/0:  /' >> "$2/log"
END=$(date +%s.%N)
DIFF=$(echo "$END - $START" | bc)
echo "1: Done " >> "$2/log"
RUNTIME=$(echo $DIFF|cut -d. -f1)
echo "1: Generation time: $RUNTIME seconds">> "$2/log"
fi
sleep 20
rm -rf "$2"
DUR

cd ${rutorrent}plugins
svn co http://svn.rutorrent.org/svn/filemanager/trunk/filemanager >/dev/null 2>&1
list="edit-3.5.tar.gz nfo-3.5.tar.gz _noty-3.5.tar.gz ss-3.5.tar.gz \
	_task-3.5.tar.gz ipad-3.5.tar.gz filedrop-3.5.tar.gz \
	create-3.5.tar.gz check_port-3.5.tar.gz mediainfo-3.5.tar.gz \
	loginmgr-3.5.tar.gz ratio-3.5.tar.gz source-3.5.tar.gz \
	rutracker_check-3.5.tar.gz rss-3.5.tar.gz history-3.5.tar.gz \
	retrackers-3.5.tar.gz autotools-3.5.tar.gz screenshots-3.5.tar.gz geoip-3.5.tar.gz"
for i in $list;do
wget -q https://rutorrent.googlecode.com/files/$i
tar -zxvf $i >/dev/null 2>&1
rm -rf $i >/dev/null 2>&1
done

wget https://github.com/geekism/rtorrent/raw/master/stream.tar >/dev/null 2>&1
tar -xvf stream.tar >/dev/null 2>&1
rm -rf stream.tar >/dev/null 2>&1
wget https://github.com/geekism/rtorrent/raw/master/ratiocolor.tar >/dev/null 2>&1
tar -xvf ratiocolor.tar >/dev/null 2>&1
rm -rf ratiocolor.tar >/dev/null 2>&1

sed -i 's/showhidden: true,/showhidden: false,/g' ${rutorrent}plugins/filemanager/init.js
cat >${rutorrent}plugins/filemanager/conf.php<<'FM'
<?php
$fm['tempdir'] = '/tmp';               // path were to store temporary data ; must be writable 
$fm['mkdperm'] = 755;          // default permission to set to new created directories
$pathToExternals['rar'] = '/usr/bin/unrar';
$pathToExternals['zip'] = '/usr/bin/zip';
$pathToExternals['unzip'] = '/usr/bin/unzip';
$pathToExternals['tar'] = '/bin/tar';
$fm['archive']['types'] = array('rar', 'zip', 'tar', 'gzip', 'bzip2');
$fm['archive']['compress'][0] = range(0, 5);
$fm['archive']['compress'][1] = array('-0', '-1', '-9');
$fm['archive']['compress'][2] = $fm['archive']['compress'][3] = $fm['archive']['compress'][4] = array(0);
?>
FM
cat >${rutorrent}plugins/screenshots/conf.php<<SS
<?php
\$pathToExternals['ffmpeg'] = '';
\$extensions = array
(
        "3g2","3gp","4xm","iff","iss","mtv","roq","a64","ac3","anm","apc","asf","avi","avm2","avs","bethsoftvid",
        "bink","c93","cavsvideo","cdg","dirac","dnxhd","dsicin","dts","dv","dv1394","dvd","ea","eac3","ffm","film_cpk",
        "filmstrip","flic","flv","gxf","h261","h263","h264","idcin","image2","image2pipe",
        "ingenient","ipmovie","ipod","iv8","ivf","m4v","matroska","mjpeg","mov","m4a","mj2",
        "mp2","mp4","mpeg","mpeg1video","mpeg2video","mpegts","mpegtsraw","mpegvideo",
        "msnwctcp","mvi","mxf","mxf_d10","nc","nsv","nuv","ogg","psp","psxstr","rawvideo","rm","rpl","rtsp",
        "smk","svcd","swf","vcd","video4linux","video4linux2","vob","webm","wmv",
        "mkv","ogm","mpg","mpv","m1v","m2v","mp2","qt","rmvb","dat","ts"
);

?>
SS
cat >${rutorrent}plugins/stream/config.php<<'ST'
<?php
$auth = '';
define('USE_NGINX', false);
define('SCHEME', 'https');
ST
chown -R www-data.www-data /srv/
}

function _autodl() {
echo -n "Installing autodl-irssi ... "
mkdir -p /home/${username}/.irssi/scripts/autorun/ >/dev/null 2>&1
cd /home/${username}/.irssi/scripts >/dev/null 2>&1
wget -O autodl-irssi.zip https://autodl-irssi-community.googlecode.com/files/autodl-irssi-community.zip >/dev/null 2>&1
unzip -o autodl-irssi.zip >/dev/null 2>&1
rm autodl-irssi.zip >/dev/null 2>&1
cp autodl-irssi.pl autorun/ >/dev/null 2>&1

mkdir -p /home/${username}/.autodl >/dev/null 2>&1
cat >/home/${username}/.autodl/autodl.cfg<<ADC
[options]
gui-server-port = ${IRSSI_PORT}
gui-server-password = ${IRSSI_PASS}
allowed = watchdir
ADC
chown -R ${username}.${username} /home/${username}/.irssi/
chown -R ${username}.${username} /home/${username}
echo ${OK}
}

function _makedirs() {
echo -n "Making ${username} directory structure ... "
mkdir /home/${username}/{torrents,.sessions,watch} >/dev/null 2>&1
chown ${username}.www-data /home/${username}/{torrents,.sessions,watch,.rtorrent.rc} >/dev/null 2>&1
usermod -a -G www-data ${username} >/dev/null 2>&1
usermod -a -G ${username} www-data >/dev/null 2>&1
echo ${OK}
}

function _fixpidof { cp /sbin/pidof /bin/pidof ; }

function _icron() {
echo -n "Writing ${username} irssi.cron ... "
cp /sbin/pidof /bin/
cat >/home/${username}/irssi.cron<<EOF
#!/bin/bash
procname=/usr/bin/irssi
sessionname='irssi'
runcmd="screen -fa -dmS \$sessionname \$procname"
username=\`id -un\`
existing_pids=\`/bin/pidof -s \$procname\`
if [[ -z \$existing_pids ]];
then
        startproc=true;
else
    	my_pid=\`ps -U ${username} -u ${username} -o pid= | grep "\$existing_pids"\`;
        if [[ -z \$my_pid ]]; then startproc=true; fi
fi
if [[ ! -z \$startproc ]];
then
	\$runcmd;
fi
EOF
chmod +x /home/${username}/irssi.cron
echo ${OK}
}

function _rcron() {
echo -n "Writing ${username} rtorrent.cron ... "
cat >/home/${username}/rtorrent.cron<<EOF
#!/bin/bash
procname=/usr/bin/rtorrent
sessionname='rtorrent'
runcmd="screen -fa -dmS \$sessionname \$procname"
username=\`id -un\`
existing_pids=\`/bin/pidof -s \$procname\`
if [[ -z \$existing_pids ]];
then
        startproc=true;
else
        my_pid=\`ps -U \${username} -u \${username} -o pid= | grep "\$existing_pids"\`;
        if [[ -z \$my_pid ]]; then startproc=true; fi
fi
if [[ ! -z \$startproc ]];
then
	find ~ -name rtorrent.lock -exec rm -rf {} \;
	find ~ -name .rtorrent.rpc -exec rm -rf {} \;
        \$runcmd;
fi
EOF
echo ${OK}
}

function _perms() {
echo -n "Setting permissions on ${username} ... "
chown -R ${username}.${username} /home/${username}/ >/dev/null 2>&1
sudo -u ${username} chmod +x /home/${username}/rtorrent.cron >/dev/null 2>&1
sudo -u ${username} chmod +x /home/${username}/irssi.cron >/dev/null 2>&1
sudo -u ${username} chmod 755 /home/${username}/ >/dev/null 2>&1
echo ${OK}
echo -n "Starting irssi/rtorrent for ${username} ... "
sudo -u ${username} /usr/bin/screen -fa -d -m -s torrent /home/${username}/rtorrent.cron >/dev/null 2>&1
sudo -u ${username} /usr/bin/screen -fa -d -m -S irssi irssi
mkdir /srv/rutorrent/conf/users/${username} >/dev/null 2>&1
echo ${OK}
}

function _ruconf() {
echo -n "Setting up irssi-autodl ... "
echo ${OK}
echo -n "Writing ${username} rutorrent config.php file ... "
cat >${rutorrent}conf/users/${username}/config.php<<EOF
<?php
  @define('HTTP_USER_AGENT', 'Mozilla/5.0 (Windows NT 6.0; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0', true);
  @define('HTTP_TIME_OUT', 30, true);
  @define('HTTP_USE_GZIP', true, true);
  \$httpIP = null;
  @define('RPC_TIME_OUT', 5, true);
  @define('LOG_RPC_CALLS', false, true);
  @define('LOG_RPC_FAULTS', true, true);
  @define('PHP_USE_GZIP', false, true);
  @define('PHP_GZIP_LEVEL', 2, true);
  \$schedule_rand = 10;
  \$do_diagnostic = true;
  \$log_file = '/tmp/errors.log';
  \$saveUploadedTorrents = true;
  \$overwriteUploadedTorrents = false;
  \$topDirectory = '/home/${username}/';
  \$forbidUserSettings = false;
  \$scgi_port = $P;
  \$scgi_host = localhost;
  \$XMLRPCMountPoint = "/RPC2";
  \$pathToExternals = array("php" => '',"curl" => '',"gzip" => '',"id" => '',"stat" => '',);
  \$localhosts = array("127.0.0.1", "localhost",);
  \$profilePath = '../share';
  \$profileMask = 0777;
  \$autodlPort = ${IRSSI_PORT};
  \$autodlPassword = "${IRSSI_PASS}";
EOF
chown -R www-data.www-data ${rutorrent}conf/users/ >/dev/null 2>&1
echo ${OK}
}

function _scripts() {
echo -n "Fetching newuser.sh chgpass.sh to /usr/sbin ... "
cd
wget -q https://raw.github.com/geekism/rtorrent/master/chgpass-debian.sh -Ochgpass
chmod +x chgpass
cp chgpass /usr/sbin
echo ${OK}
}

function _boot() {
echo -n "Setting irssi/rtorrent to start on boot ... "
tmpfile="/tmp/`perl -le 'print map {(a..z,A..Z,0..9)[rand 62] } 0..pop' 8`"
touch $tmpfile
echo "*/1 * * * * /home/${username}/rtorrent.cron">>$tmpfile
echo "*/1 * * * * /home/${username}/irssi.cron">>$tmpfile
sudo -u ${username} crontab $tmpfile
rm -rf $tmpfile
service apache2 restart >/dev/null 2>&1
echo ${OK}
}

function _finished() {
echo "COMPLETED in ${FIN}/min"
echo "Seedbox can be found at http://${username}:${passwd}@$ip (it will redirect to SSL by default)"
}

_intro
_update
_depends
_askffmpeg
if [[ ${ffmpeg} == "yes" ]]; then
_ffmpeg
fi
_xmlrpc
_libtorrent
_rtorrent
_scgi
_apacheconf
_rutorrent
_adduser
_rconf
_plugins
_autodl
_makedirs
_fixpidof
_icron
_rcron
_perms
_ruconf
_scripts
_boot
E=`date +%s`;DIFF=`expr $E - $S`;FIN=`expr $DIFF / 60`
_finished
