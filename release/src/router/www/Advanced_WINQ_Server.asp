<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title><#686#> - <#120#></title>
<link rel="stylesheet" type="text/css" href="index_style.css">
<link rel="stylesheet" type="text/css" href="form_style.css">
<link rel="stylesheet" type="text/css" href="menu_style.css">
<script language="JavaScript" type="text/javascript" src="/help.js"></script>
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" language="JavaScript" src="/base64.js"></script>
<script language="JavaScript" type="text/javascript" src="/validator.js"></script>
<script type="text/javascript" src="/js/jquery.js"></script>
<script type="text/javascript" src="/switcherplugin/jquery.iphone-switch.js"></script>
<script language="JavaScript" type="text/javascript" src="/form.js"></script>
<script type="text/javascript" src="/js/httpApi.js"></script>
<style type="text/css">
.contentM_qis{
width:740px;
margin-top:280px;
margin-left:380px;
position:absolute;
-webkit-border-radius: 5px;
-moz-border-radius: 5px;
border-radius: 5px;
z-index:200;
background-color:#2B373B;
box-shadow: 3px 3px 10px #000;
display:none;
/*behavior: url(/PIE.htc);*/
}
.QISform_wireless{
width:600px;
font-size:12px;
color:#FFFFFF;
margin-top:10px;
*margin-left:10px;
}
.QISform_wireless th{
padding-left:10px;
*padding-left:30px;
font-size:12px;
font-weight:bolder;
color: #FFFFFF;
text-align:left;
}
.description_down{
margin-top:10px;
margin-left:10px;
padding-left:5px;
font-weight:bold;
line-height:140%;
color:#ffffff;
}
</style>
<script>
window.onresize = function() {
if(document.getElementById("tlsKey_panel").style.display == "block") {
cal_panel_block("tlsKey_panel", 0.15);
}
}
<% wanlink(); %>
<% vpn_server_get_parameter(); %>;
var vpn_server_clientlist_array_ori = '<% nvram_char_to_ascii("","vpn_serverx_clientlist"); %>';
var vpn_server_clientlist_array = decodeURIComponent(vpn_server_clientlist_array_ori);
var openvpn_unit = '<% nvram_get("vpn_server_unit"); %>';
var vpn_server_mode = 'openvpn'; // Hardcoded for this page, as we support both simultaneously
var openvpn_eas = '<% nvram_get("vpn_serverx_start"); %>';
var vpn_server_enable = (openvpn_eas.indexOf(''+(openvpn_unit)) >= 0) ? "1" : "0";
var service_state = "";
if (openvpn_unit == '1')
service_state = '<% nvram_get("vpn_server1_state"); %>';
else if (openvpn_unit == '2')
service_state = '<% nvram_get("vpn_server2_state"); %>';
else
service_state = false;
var openvpnd_connected_clients = [];
var openvpn_clientlist_array = decodeURIComponent('<% nvram_char_to_ascii("", "vpn_server_ccd_val"); %>');
var ciphersarray = [
["AES-128-CBC"],
["AES-192-CBC"],
["AES-256-CBC"],
["AES-128-GCM"],
["AES-192-GCM"],
["AES-256-GCM"],
["BF-CBC"],
["CAST5-CBC"],
["CAMELLIA-128-CBC"],
["CAMELLIA-192-CBC"],
["CAMELLIA-256-CBC"],
["DES-CBC"],
["DES-EDE-CBC"],
["DES-EDE3-CBC"],
["DESX-CBC"],
["IDEA-CBC"],
["SEED-CBC"]
];
var hmacarray = [
["MD 5", "MD5"],
["SHA 1", "SHA1"],
["SHA 224", "SHA224"],
["SHA 256", "SHA256"],
["SHA 384", "SHA384"],
["SHA 512", "SHA512"],
["RIPEMD 160", "RIPEMD160"],
["RSA MD4", "RSA-MD4"]
];
var wans_mode ='<% nvram_get("wans_mode"); %>';
function initial(){
var current_server_igncrt = "<% nvram_get("vpn_server_igncrt"); %>";
var currentcipher = "<% nvram_get("vpn_server_cipher"); %>";
var currentdigest = "<% nvram_get("vpn_server_digest"); %>";
show_menu();
if(pptpd_support && openvpnd_support) {
document.getElementById("divSwitchMenu").style.display = "";
}
formShowAndHide(vpn_server_enable, "openvpn");
/*Advanced Setting start */
allowed_openvpn_clientlist();
add_option(document.form.vpn_server_cipher, "Default","default",(currentcipher == "default"));
add_option(document.form.vpn_server_cipher, "None","none",(currentcipher == "none"));
for(var i = 0; i < ciphersarray.length; i += 1){
add_option(document.form.vpn_server_cipher, ciphersarray[i][0], ciphersarray[i][0], (currentcipher == ciphersarray[i][0]));
}
add_option(document.form.vpn_server_digest, "Default","default",(currentdigest == "default"));
add_option(document.form.vpn_server_digest, "None","none",(currentdigest == "none"));
for(var i = 0; i < hmacarray.length; i += 1){
add_option(document.form.vpn_server_digest, hmacarray[i][0], hmacarray[i][1], (currentdigest == hmacarray[i][1]));
}
document.form.VPNServer_enable.value = vpn_server_enable;
updateCRTValue();
enable_server_igncrt(current_server_igncrt);
update_cipher();
update_digest();
/*Advanced Setting end */
var vpn_server_array = { "PPTP" : ["PPTP", "Advanced_VPN_PPTP.asp"], "OpenVPN" : ["OpenVPN", "Advanced_VPN_OpenVPN.asp"], "IPSEC" : ["IPSec VPN", "Advanced_VPN_IPSec.asp"]};
if(!pptpd_support) {
delete vpn_server_array.PPTP;
}
if(!openvpnd_support) {
delete vpn_server_array.OpenVPN;
}
if(!ipsec_srv_support) {
delete vpn_server_array.IPSEC;
}
$('#divSwitchMenu').html(gen_switch_menu(vpn_server_array, "OpenVPN"));
/*setTimeout("show_warning_message();", 100);*/
httpApi.faqURL("faq_windows", "1004469", "https://www.asus.com", "/support/FAQ/");
httpApi.faqURL("faq_macOS", "1004472", "https://www.asus.com", "/support/FAQ/");
httpApi.faqURL("faq_iPhone", "1004471", "https://www.asus.com", "/support/FAQ/");
httpApi.faqURL("faq_android", "1004466", "https://www.asus.com", "/support/FAQ/");
var cust2 = document.form.vpn_server_cust2.value;
if (isSupport("hnd")) {
document.getElementById("vpn_server_custom_x").maxLength = 170 * 3; // 255*3 - base64 overhead
cust2 += document.form.vpn_server_cust21.value +
document.form.vpn_server_cust22.value;
}
if (based_modelid == "RT-AX88U") {
showhide("show_pass_div", 0);
}
document.getElementById("vpn_server_custom_x").value = Base64.decode(cust2);
}
var MAX_RETRY_NUM = 5;
var external_ip_retry_cnt = MAX_RETRY_NUM;
function show_warning_message(){
if(realip_support && wans_mode != "lb"){
if(realip_state != "2" && external_ip_retry_cnt > 0){
if( external_ip_retry_cnt == MAX_RETRY_NUM )
get_real_ip();
else
setTimeout("get_real_ip();", 3000);
}
else if(realip_state != "2"){
if(validator.isPrivateIP(wanlink_ipaddr())){
document.getElementById("privateIP_notes").innerHTML = "<#2793#>";
document.getElementById("privateIP_notes").style.display = "";
httpApi.faqURL("faq_port_forwarding", "1033906", "https://www.asus.com", "/support/FAQ/"); //this id is include in string : #vpn_privateIP_hint#
}
}
else{
if(!external_ip){
document.getElementById("privateIP_notes").innerHTML = "<#2793#>";
document.getElementById("privateIP_notes").style.display = "";
httpApi.faqURL("faq_port_forwarding", "1033906", "https://www.asus.com", "/support/FAQ/"); //this id is include in string : #vpn_privateIP_hint#
}
}
}
else if(validator.isPrivateIP(wanlink_ipaddr())){
document.getElementById("privateIP_notes").innerHTML = "<#2793#>";
document.getElementById("privateIP_notes").style.display = "";
httpApi.faqURL("faq_port_forwarding", "1033906", "https://www.asus.com", "/support/FAQ/"); //this id is include in string : #vpn_privateIP_hint#
}
}
function get_real_ip(){
$.ajax({
url: 'get_real_ip.asp',
dataType: 'script',
error: function(xhr){
get_real_ip();
},
success: function(response){
external_ip_retry_cnt--;
show_warning_message();
}
});
}
function formShowAndHide(server_enable, server_type) {
if(server_enable == 1){
document.getElementById("trVPNServerMode").style.display = "";
document.getElementById("selSwitchMode").value = "1";
document.getElementById("trRSAEncryptionBasic").style.display = ("<% nvram_get("vpn_server_crypt"); %>" == "secret")?"none":"";
document.getElementById("trClientWillUseVPNToAccess").style.display = "";
document.getElementById('openvpn_export').style.display = "";
document.getElementById('OpenVPN_setting').style.display = "";
document.getElementById("divAdvanced").style.display = "none";
if(vpn_server_enable == '0') {
document.getElementById('openvpn_export').style.display = "none";
document.getElementById('openvpn_export_cert').style.display = "none";
document.getElementById('openvpn_import_cert').style.display = "none";
}
else {
document.getElementById('openvpn_export').style.display = "";
document.getElementById('openvpn_export_cert').style.display = "";
document.getElementById('openvpn_import_cert').style.display = "";
}
if(service_state == false || service_state != '2')
document.getElementById('export_div').style.display = "none";
if(!email_support)
document.getElementById('exportViaEmail').style.display = "none";
showopenvpnd_clientlist();
update_vpn_client_state();
openvpnd_connected_status();
check_vpn_server_state();
document.getElementById("divApply").style.display = "";
}
else{
document.getElementById("trVPNServerMode").style.display = "none";
document.getElementById("openvpn_export").style.display = "none";
document.getElementById('openvpn_export_cert').style.display = "none";
document.getElementById('openvpn_import_cert').style.display = "none";
document.getElementById("trRSAEncryptionBasic").style.display = "none";
document.getElementById("trClientWillUseVPNToAccess").style.display = "none";
document.getElementById("OpenVPN_setting").style.display = "none";
document.getElementById("divAdvanced").style.display = "none";
}
}
function openvpnd_connected_status(){
var rule_num = document.getElementById("openvpnd_clientlist_table").rows.length;
var username_status = "";
for(var x=0; x < rule_num; x++){
var ind = x;
username_status = "conn"+ind;
if(openvpnd_connected_clients.length >0){
if(document.getElementById(username_status)) {
document.getElementById(username_status).innerHTML = '<#157#>';
}
for(var y=0; y<openvpnd_connected_clients.length; y++){
if(document.getElementById("openvpnd_clientlist_table").rows[x].cells[1].title == openvpnd_connected_clients[y].username){
document.getElementById(username_status).innerHTML = '<a class="hintstyle2" href="javascript:void(0);" onClick="showOpenVPNClients(\''+openvpnd_connected_clients[y].username+'\');"><#133#></a>';
break;
}
}
}else if(document.getElementById(username_status)){
document.getElementById(username_status).innerHTML = '<#157#>';
}
}
}
function applyRule(){
var validForm = function() {
if (!validator.numberRange(document.form.vpn_server_port, 1, 65535) ||
!validator.numberRange(document.form.vpn_server_verb, 0, 6))
{
return false;
}
return true;
};
if(!validForm())
return false;
var confirmFlag = true;
/* Advanced setting start */
var check_openvpn_conflict = function () { //if conflict with LAN ip & DHCP ip pool & static
var origin_lan_ip = '<% nvram_get("lan_ipaddr"); %>';
var lan_ip_subnet = origin_lan_ip.split(".")[0]+"."+origin_lan_ip.split(".")[1]+"."+origin_lan_ip.split(".")[2]+".";
var lan_ip_end = parseInt(origin_lan_ip.split(".")[3]);
var pool_start = '<% nvram_get("dhcp_start"); %>';
var pool_end = '<% nvram_get("dhcp_end"); %>';
var dhcp_staticlists = "<% nvram_get("dhcp_staticlist"); %>";
var staticclist_row = dhcp_staticlists.split('&#60');
var netmask_obj = document.form.vpn_server_nm;
var vpnSubnet = document.form.vpn_server_sn;
var pool_start = '<% nvram_get("dhcp_start"); %>';
var pool_subnet = pool_start.split(".")[0]+"."+pool_start.split(".")[1]+"."+pool_start.split(".")[2]+".";
if (isSupport("hnd"))
split_custom2(Base64.encode(document.getElementById("vpn_server_custom_x").value));
else
document.form.vpn_server_cust2.value = Base64.encode(document.getElementById("vpn_server_custom_x").value);
if(document.form.vpn_server_if.value == 'tun'){
if(vpnSubnet.value == ""){
alert("<#209#>");
vpnSubnet.focus();
vpnSubnet.select();
return false;
}
if(!validator.ipRange(vpnSubnet, "")){
vpnSubnet.focus();
vpnSubnet.select();
return false;
}
var openvpn_server_subnet = vpnSubnet.value.split(".")[0]
+ "." + vpnSubnet.value.split(".")[1]
+ "." + vpnSubnet.value.split(".")[2]
+ ".";
if(origin_lan_ip == vpnSubnet.value) {
alert("<#2738#> " + origin_lan_ip);
vpnSubnet.focus();
vpnSubnet.select();
return false;
}
if(lan_ip_subnet == openvpn_server_subnet) {
alert("<#2736#>"+pool_start+" ~ "+pool_end);
vpnSubnet.focus();
vpnSubnet.select();
return false;
}
if(!validator.maskRange("255.255.0.0", "255.255.255.248", netmask_obj.value)) {
alert("Netmask range must be 255.255.0.0 (/16) ~ 255.255.255.248 (/29)");
netmask_obj.focus();
netmask_obj.select();
return false;
}
if(!validator.subnetAndMaskCombination(vpnSubnet.value, netmask_obj.value)) {
alert(vpnSubnet.value + " / " + netmask_obj.value + " combination is invalid");
vpnSubnet.focus();
vpnSubnet.select();
return false;
}
}
else if(document.form.vpn_server_if.value == 'tap' && document.form.vpn_server_dhcp.value == '0'){
if(!validator.isLegalIP(document.form.vpn_server_r1, "")){
document.form.vpn_server_r1.focus();
document.form.vpn_server_r1.select();
return false;
}
if(document.form.vpn_server_r1.value.split(".")[3] == 255){ //*.*.*.255 can't be IP in the IP pool
alert(document.form.vpn_server_r1.value + " <#219#>");
document.form.vpn_server_r1.focus();
document.form.vpn_server_r1.select();
return false;
}
if(!validator.isLegalIP(document.form.vpn_server_r2, "")){
document.form.vpn_server_r2.focus();
document.form.vpn_server_r2.select();
return false;
}
if(document.form.vpn_server_r2.value.split(".")[3] == 255){ //*.*.*.255 can't be IP in the IP pool
alert(document.form.vpn_server_r2.value + " <#219#>");
document.form.vpn_server_r2.focus();
document.form.vpn_server_r2.select();
return false;
}
var openvpn_clients_start_subnet = document.form.vpn_server_r1.value.split(".")[0] + "."
+ document.form.vpn_server_r1.value.split(".")[1] + "."
+ document.form.vpn_server_r1.value.split(".")[2] + ".";
var openvpn_clients_end_subnet = document.form.vpn_server_r2.value.split(".")[0] + "."
+ document.form.vpn_server_r2.value.split(".")[1] + "."
+ document.form.vpn_server_r2.value.split(".")[2] + ".";
var openvpn_clients_start_ip = parseInt(document.form.vpn_server_r1.value.split(".")[3]);
var openvpn_clients_end_ip = parseInt(document.form.vpn_server_r2.value.split(".")[3]);
if( (lan_ip_subnet == openvpn_clients_start_subnet || lan_ip_subnet == openvpn_clients_end_subnet)
&& (lan_ip_end >= openvpn_clients_start_ip && lan_ip_end <= openvpn_clients_end_ip)) {
alert("<#2738#> "+origin_lan_ip);
document.form.vpn_server_r1.focus();
document.form.vpn_server_r1.select();
return false;
}
if(openvpn_clients_end_ip < openvpn_clients_start_ip){
alert(document.form.vpn_server_r2.value + " <#219#>");
document.form.vpn_server_r2.focus();
document.form.vpn_server_r2.select();
return false;
}
if(pool_subnet != openvpn_clients_start_subnet) {
alert(document.form.vpn_server_r1.value + " <#219#>");
document.form.vpn_server_r1.focus();
document.form.vpn_server_r1.select();
return false;
}
if(pool_subnet != openvpn_clients_end_subnet) {
alert(document.form.vpn_server_r2.value + " <#219#>");
document.form.vpn_server_r2.focus();
document.form.vpn_server_r2.select();
return false;
}
if(dhcp_staticlists != "") {
for(var i = 1; i < staticclist_row.length; i +=1 ) {
var static_ip = staticclist_row[i].split('&#62')[1];
var static_subnet = static_ip.split(".")[0]+"."+static_ip.split(".")[1]+"."+static_ip.split(".")[2]+".";
var static_end = parseInt(static_ip.split(".")[3]);
if(static_subnet != openvpn_clients_start_subnet) {
alert(document.form.vpn_server_r1.value + " <#219#>");
document.form.vpn_server_r1.focus();
document.form.vpn_server_r1.select();
return false;
}
if(static_subnet != openvpn_clients_end_subnet) {
alert(document.form.vpn_server_r2.value + " <#219#>");
document.form.vpn_server_r2.focus();
document.form.vpn_server_r2.select();
return false;
}
}
}
}
return true;
};
/* Advanced setting end */
if(confirmFlag && check_openvpn_conflict() ) {
document.openvpnTLSKeyForm.vpn_crt_server1_ca.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server1_crt.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server1_key.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server1_dh.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server1_crl.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server1_extra.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server1_static.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server2_ca.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server2_crt.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server2_key.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server2_dh.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server2_crl.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server2_static.disabled = true;
document.openvpnTLSKeyForm.vpn_crt_server2_extra.disabled = true;
var get_group_value = function () {
var rule_num = document.getElementById("openvpnd_clientlist_table").rows.length;
var item_num = document.getElementById("openvpnd_clientlist_table").rows[0].cells.length;
var tmp_value = "";
for(var i = 1; i < rule_num; i += 1) {
tmp_value += "<"
for(var j = 1; j < item_num - 1; j += 1) {
if (j == 2) { // Password
tmp_value += overlib_str3[i];
}
else if(document.getElementById("openvpnd_clientlist_table").rows[i].cells[j].innerHTML.lastIndexOf("...") < 0) {
tmp_value += document.getElementById("openvpnd_clientlist_table").rows[i].cells[j].innerHTML;
}
else {
tmp_value += document.getElementById("openvpnd_clientlist_table").rows[i].cells[j].title;
}
if(j != item_num - 2)
tmp_value += ">";
}
}
if(tmp_value == "<"+"<#1802#>" || tmp_value == "<")
tmp_value = "";
return tmp_value;
};
if (service_state) {
document.form.action_script.value = "restart_vpnserver" + openvpn_unit;
}
if(document.form.VPNServer_enable.value == "1") {
document.form.VPNServer_mode.value = 'openvpn';
document.form.action_script.value = "restart_chpass;restart_vpnserver" + openvpn_unit;
document.form.vpn_serverx_clientlist.value = get_group_value();
/* Advanced setting start */
var getAdvancedValue = function () {
var client_num = document.getElementById("openvpn_clientlist_table").rows.length;
var item_num = document.getElementById("openvpn_clientlist_table").rows[0].cells.length;
var tmp_value = "";
for(var i = 0; i < client_num; i += 1) {
tmp_value += "<1>";
for(var j = 0; j < item_num - 1; j += 1) {
if (j == 3)
tmp_value += (document.getElementById("openvpn_clientlist_table").rows[i].cells[j].innerHTML == "Yes" ? 1 : 0);
else
tmp_value += document.getElementById("openvpn_clientlist_table").rows[i].cells[j].innerHTML;
if(j != item_num - 2)
tmp_value += ">";
}
}
if(tmp_value == "<"+"<#1802#>" || tmp_value == "<1>")
tmp_value = "";
document.form.vpn_server_ccd_val.value = tmp_value;
if (document.form.vpn_server_pdns.value != "<% nvram_get("vpn_server_pdns"); %>")
document.form.action_script.value += ";restart_dnsmasq";
}();
/* Advanced setting end */
}
else { //disable server
document.form.action_script.value = "stop_vpnserver" + openvpn_unit;
document.form.vpn_serverx_clientlist.value = get_group_value();
}
showLoading();
document.form.submit();
}
}
function split_custom2(cust2){
var counter = 0;
document.form.vpn_server_cust2.value = cust2.substring(counter, (counter+=255));
document.form.vpn_server_cust21.value = cust2.substring(counter, (counter+=255));
document.form.vpn_server_cust22.value = cust2.substring(counter, (counter+=255));
}
function addRow(obj, head){
if(head == 1)
vpn_server_clientlist_array += "<" /*&#60*/
else
vpn_server_clientlist_array += ">" /*&#62*/
vpn_server_clientlist_array += obj.value;
obj.value = "";
}
function validForm(){
var valid_username = document.form.vpn_server_clientlist_username;
var valid_password = document.form.vpn_server_clientlist_password;
if(valid_username.value == "") {
alert("<#209#>");
valid_username.focus();
return false;
}
else if(!Block_chars(valid_username, [" ", "@", "*", "+", "|", ":", "?", "<", ">", ",", ".", "/", ";", "[", "]", "\\", "=", "\"", "&", "#" ])) {
return false;
}
if(valid_password.value == "") {
alert("<#209#>");
valid_password.focus();
return false;
}
else if(!Block_chars(valid_password, ["<", ">", "&"])) {
return false;
}
return true;
}
function addRow_Group(upper){
var username_obj = document.form.vpn_server_clientlist_username;
var password_obj = document.form.vpn_server_clientlist_password;
var rule_num = document.getElementById("openvpnd_clientlist_table").rows.length;
var item_num = document.getElementById("openvpnd_clientlist_table").rows[0].cells.length;
if(rule_num >= upper) {
alert("<#1852#> " + upper + " <#1853#>");
return false;
}
if(validForm()){
if(item_num >= 2) {
for(var i = 0; i < rule_num; i += 1) {
if(username_obj.value == document.getElementById("openvpnd_clientlist_table").rows[i].cells[1].title) {
alert("<#1846#>");
username_obj.focus();
username_obj.select();
return false;
}
}
}
addRow(username_obj ,1);
addRow(password_obj, 0);
showopenvpnd_clientlist();
openvpnd_connected_status();
}
}
function del_Row(rowdata){
var i = rowdata.parentNode.parentNode.rowIndex;
document.getElementById("openvpnd_clientlist_table").deleteRow(i);
overlib_str3.splice(i,1);
var vpn_server_clientlist_value = "";
var rowLength = document.getElementById("openvpnd_clientlist_table").rows.length;
for(var k = 1; k < rowLength; k += 1){
vpn_server_clientlist_value += "<";
if (document.getElementById("openvpnd_clientlist_table").rows[k].cells[1].innerHTML.lastIndexOf("...") < 0)
vpn_server_clientlist_value += document.getElementById("openvpnd_clientlist_table").rows[k].cells[1].innerHTML;
else
vpn_server_clientlist_value += document.getElementById("openvpnd_clientlist_table").rows[k].cells[1].title;
vpn_server_clientlist_value += ">";
vpn_server_clientlist_value += overlib_str3[k];
}
vpn_server_clientlist_array = vpn_server_clientlist_value;
if(vpn_server_clientlist_array == "") {
showopenvpnd_clientlist();
openvpnd_connected_status();
}
}
var overlib_str2 = new Array(); //Viz add 2013.10 for record longer VPN client username/pwd for OpenVPN
var overlib_str3 = new Array(); //Viz add 2013.10 for record longer VPN client username/pwd for OpenVPN
function showopenvpnd_clientlist(){
var vpn_server_clientlist_row = vpn_server_clientlist_array.split('<');
var code = "";
code +='<table width="100%" cellspacing="0" cellpadding="4" align="center" class="list_table" id="openvpnd_clientlist_table">';
code +='<tr id="row0"><td width="15%" id="conn0"></td><td width="35%" title="<% nvram_get("http_username"); %>"><% nvram_get("http_username"); %></td><td width="35%" style="text-align:center;">-</td><td width="15%" style="text-align:center;">-</td></tr>';
if(vpn_server_clientlist_row.length > 1){
for(var i = 1; i < vpn_server_clientlist_row.length; i++){
overlib_str2[i] = "";
overlib_str3[i] = "";
code +='<tr id="row'+i+'">';
var vpn_server_clientlist_col = vpn_server_clientlist_row[i].split('>');
code +='<td width="15%" id="conn'+i+'"></td>';
for(var j = 0; j < vpn_server_clientlist_col.length; j++){
if(j == 0){
if(vpn_server_clientlist_col[0].length >32){
overlib_str2[i] = vpn_server_clientlist_col[0];
vpn_server_clientlist_col[0] = vpn_server_clientlist_col[0].substring(0, 30)+"...";
code +='<td width="35%" title="'+overlib_str2[i]+'">'+ vpn_server_clientlist_col[0] +'</td>';
}else{
code +='<td width="35%" title="'+vpn_server_clientlist_col[0]+'">'+ vpn_server_clientlist_col[0] +'</td>';
}
}
else if(j ==1){
overlib_str3[i] = vpn_server_clientlist_col[1];
if (document.getElementById('show_pass').checked == false) {
code +='<td width="35%">*****</td>';
}else if(vpn_server_clientlist_col[1].length >32){
vpn_server_clientlist_col[1] = vpn_server_clientlist_col[1].substring(0, 30)+"...";
code +='<td width="35%" title="'+overlib_str3[i]+'">'+ vpn_server_clientlist_col[1] +'</td>';
}else{
code +='<td width="35%">'+ vpn_server_clientlist_col[1] +'</td>';
}
}
}
code +='<td width="15%">';
code +='<input class="remove_btn" onclick="del_Row(this, \'openvpnd\');" value=""/></td></tr>';
}
}
code +='</table>';
document.getElementById("openvpnd_clientlist_Block").innerHTML = code;
}
function parseOpenVPNClients(client_status){ //192.168.123.82:46954 10.8.0.6 pine\n
openvpnd_connected_clients = [];
var Loginfo = client_status;
if (Loginfo == "") {return;}
Loginfo = Loginfo.replace('\r\n', '\n');
Loginfo = Loginfo.replace('\n\r', '\n');
Loginfo = Loginfo.replace('\r', '\n');
var lines = Loginfo.split('\n');
for (i = 0; i < lines.length; i++){
var fields = lines[i].split(' ');
if ( fields.length != 3 ) continue;
openvpnd_connected_clients.push({"username":fields[2],"remoteIP":fields[0],"VPNIP":fields[1]});
}
}
function showOpenVPNClients(uname){
var statusmenu = "";
var statustitle = "";
statustitle += "<div style=\"text-decoration:underline;\">VPN IP ( Remote IP )</div>";
_caption = statustitle;
for (i = 0; i < openvpnd_connected_clients.length; i++){
if(uname == openvpnd_connected_clients[i].username){
statusmenu += "<div>"+openvpnd_connected_clients[i].VPNIP+" \t( "+openvpnd_connected_clients[i].remoteIP+" )</div>";
}
}
return overlib(statusmenu, WIDTH, 260, OFFSETX, -360, LEFT, STICKY, CAPTION, _caption, CLOSETITLE, '');
}
function check_vpn_server_state(){
if(vpn_server_enable == '1' && service_state != '2'){
document.getElementById('export_div').style.display = "none";
document.getElementById('openvpn_initial').style.display = "";
update_vpn_server_state();
}
}
function update_vpn_server_state() {
$.ajax({
url: '/ajax_openvpn_server.asp',
dataType: 'script',
error: function(xhr) {
setTimeout("update_vpn_server_state();", 1000);
},
success: function() {
if(vpnd_state != '2' && (vpnd_errno == '1' || vpnd_errno == '2')){
document.getElementById('openvpn_initial').style.display = "none";
document.getElementById('openvpn_error_message').innerHTML = "<span><#2762#></span>";
document.getElementById('openvpn_error_message').style.display = "";
}
else if(vpnd_state != '2' && vpnd_errno == '4'){
document.getElementById('openvpn_initial').style.display = "none";
document.getElementById('openvpn_error_message').innerHTML = "<span><#2763#></span>";
document.getElementById('openvpn_error_message').style.display = "";
}
else if(vpnd_state != '2' && vpnd_errno == '5'){
document.getElementById('openvpn_initial').style.display = "none";
document.getElementById('openvpn_error_message').innerHTML = "<span><#2764#></span>";
document.getElementById('openvpn_error_message').style.display = "";
}
else if(vpnd_state == '-1' && vpnd_errno == '0'){
document.getElementById('openvpn_initial').style.display = "none";
document.getElementById('openvpn_error_message').innerHTML = "<span><#2765#></span>";
document.getElementById('openvpn_error_message').style.display = "";
}
else if(vpnd_state != '2'){
setTimeout("update_vpn_server_state();", 1000);
}
else{ // OpenVPN server ready , vpn_server1_state==2
setTimeout("location.href='Advanced_VPN_OpenVPN.asp';", 1000);
return;
}
}
});
}
function showMailPanel(){
var checker = {
server: document.mailConfigForm.PM_SMTP_SERVER.value,
mailPort: document.mailConfigForm.PM_SMTP_PORT.value,
user: document.mailConfigForm.PM_SMTP_AUTH_USER.value,
pass: document.mailConfigForm.PM_SMTP_AUTH_PASS.value,
end: 0
}
if(checker.server == "" || checker.mailPort == "" || checker.user == "" || checker.pass == ""){
$("#mailConfigPanelContainer").fadeIn(300);
$("#mailSendPanelContainer").fadeOut(300);
}
else{
$("#mailConfigPanelContainer").fadeOut(300);
$("#mailSendPanelContainer").fadeIn(300);
}
}
function switchMode(mode){
if(mode == "1"){ //general setting
document.getElementById("trRSAEncryptionBasic").style.display = ("<% nvram_get("vpn_server_crypt"); %>" == "secret")?"none":"";
document.getElementById("trClientWillUseVPNToAccess").style.display = "";
document.getElementById("OpenVPN_setting").style.display = "";
if(vpn_server_enable == '0') {
document.getElementById('openvpn_export').style.display = "none";
document.getElementById('openvpn_export_cert').style.display = "none";
document.getElementById('openvpn_import_cert').style.display = "none";
}
else {
document.getElementById('openvpn_export').style.display = "";
document.getElementById('openvpn_export_cert').style.display = "";
document.getElementById('openvpn_import_cert').style.display = "";
}
document.getElementById("divAdvanced").style.display = "none";
}
else{
document.getElementById("trRSAEncryptionBasic").style.display = "none";
document.getElementById("trClientWillUseVPNToAccess").style.display = "none";
document.getElementById("OpenVPN_setting").style.display = "none";
document.getElementById("openvpn_export").style.display = "none";
document.getElementById('openvpn_export_cert').style.display = "none";
document.getElementById('openvpn_import_cert').style.display = "none";
document.getElementById("divAdvanced").style.display = "";
}
}
function enable_openvpn(state){
var tmp_value = "";
for (var i=1; i < 3; i++) {
if (i == openvpn_unit) {
if (state == 1)
tmp_value += ""+i+",";
} else {
if (document.form.vpn_serverx_start.value.indexOf(''+(i)) >= 0)
tmp_value += ""+i+","
}
}
document.form.vpn_serverx_start.value = tmp_value;
}
/* Advanced Setting start */
function change_vpn_unit(val){
FormActions("apply.cgi", "change_vpn_server_unit", "", "");
document.form.target = "";
document.form.submit();
}
function update_visibility(){
var auth = document.form.vpn_server_crypt.value;
var iface = document.form.vpn_server_if.value;
var hmac = document.form.vpn_server_hmac.value;
userpass = getRadioValue(document.form.vpn_server_userpass_auth);
var dhcp = getRadioValue(document.form.vpn_server_dhcp);
if(auth != "tls")
ccd = 0;
else
ccd = getRadioValue(document.form.vpn_server_ccd);
ncp = document.form.vpn_server_ncp_enable.value;
comp = document.form.vpn_server_comp.value;
showhide("server_authhmac", (auth != "secret"));
showhide("server_snnm", ((auth == "tls") && (iface == "tun")));
showhide("server_local", ((auth == "secret") && (iface == "tun")));
showhide("server_ccd", (auth == "tls"));
showhide("server_c2c", ccd);
showhide("server_ccd_excl", ccd);
showhide("openvpn_client_table", ccd);
showhide("openvpn_clientlist_Block", ccd);
showhide("server_pdns", (auth == "tls") );
showhide("server_dhcp",((auth == "tls") && (iface == "tap")));
showhide("server_range", ((dhcp == 0) && (auth == "tls") && (iface == "tap")));
showhide("server_tls_crypto_tr", ((auth == "tls") || (auth == "secret"))); //add by Viz
showhide("server_igncrt", (userpass == 1));
showhide("server_cipher", (ncp != 2));
showhide("ncp_enable", (auth == "tls"));
showhide("ncp_ciphers", ((ncp > 0) && (auth == "tls")));
/* Warn if exported ovpn requires OpenVPN 2.4.0 */
showhide("ncp_24_warn", (ncp > 0));
showhide("comp_24_warn", (comp == "lz4") || (comp == "lz4-v2"));
showhide("tlscrypt_24_warn", (hmac == 3));
}
function edit_Keys() {
cal_panel_block("tlsKey_panel", 0.15);
$("#tlsKey_panel").fadeIn(300);
}
function updateCRTValue(){
$.ajax({
url: '/ajax_openvpn_server.asp',
dataType: 'script',
timeout: 1500,
error: function(xhr){
setTimeout("updateCRTValue();",1000);
},
success: function(){
if (openvpn_unit == 1) {
document.openvpnTLSKeyForm.edit_vpn_crt_server_ca.value = vpn_crt_server1_ca[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
document.openvpnTLSKeyForm.edit_vpn_crt_server_crt.value = vpn_crt_server1_crt[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
document.openvpnTLSKeyForm.edit_vpn_crt_server_key.value = vpn_crt_server1_key[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
document.openvpnTLSKeyForm.edit_vpn_crt_server_dh.value = vpn_crt_server1_dh[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
document.openvpnTLSKeyForm.edit_vpn_crt_server_crl.value = vpn_crt_server1_crl[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
document.openvpnTLSKeyForm.edit_vpn_crt_server_static.value = vpn_crt_server1_static[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
document.openvpnTLSKeyForm.edit_vpn_crt_server_extra.value = vpn_crt_server1_extra[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
} else if (openvpn_unit == 2) {
document.openvpnTLSKeyForm.edit_vpn_crt_server_ca.value = vpn_crt_server2_ca[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
document.openvpnTLSKeyForm.edit_vpn_crt_server_crt.value = vpn_crt_server2_crt[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
document.openvpnTLSKeyForm.edit_vpn_crt_server_key.value = vpn_crt_server2_key[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
document.openvpnTLSKeyForm.edit_vpn_crt_server_dh.value = vpn_crt_server2_dh[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
document.openvpnTLSKeyForm.edit_vpn_crt_server_crl.value = vpn_crt_server2_crl[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
document.openvpnTLSKeyForm.edit_vpn_crt_server_static.value = vpn_crt_server2_static[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
document.openvpnTLSKeyForm.edit_vpn_crt_server_extra.value = vpn_crt_server2_extra[0].replace(/&#10/g, "\n").replace(/&#13/g, "\r");
}
}
})
}
function addRow_Group_Advanced(upper){
var client_num = document.getElementById("openvpn_clientlist_table").rows.length;
var item_num = document.getElementById("openvpn_clientlist_table").rows[0].cells.length;
if(client_num >= upper){
alert("<#1852#> " + upper + " <#1853#>");
return false;
}
if(document.form.vpn_clientlist_commonname_0.value==""){
alert("<#209#>");
document.form.vpn_clientlist_commonname_0.focus();
document.form.vpn_clientlist_commonname_0.select();
return false;
}
if(document.form.vpn_clientlist_subnet_0.value==""){
alert("<#209#>");
document.form.vpn_clientlist_subnet_0.focus();
document.form.vpn_clientlist_subnet_0.select();
return false;
}
if(document.form.vpn_clientlist_netmask_0.value==""){
alert("<#209#>");
document.form.vpn_clientlist_netmask_0.focus();
document.form.vpn_clientlist_netmask_0.select();
return false;
}
if(item_num >=2){
for(i=0; i<client_num; i++){
if(document.form.vpn_clientlist_commonname_0.value.toLowerCase() == document.getElementById("openvpn_clientlist_table").rows[i].cells[0].innerHTML.toLowerCase()
&& document.form.vpn_clientlist_subnet_0.value == document.getElementById("openvpn_clientlist_table").rows[i].cells[1].innerHTML
&& document.form.vpn_clientlist_netmask_0.value == document.getElementById("openvpn_clientlist_table").rows[i].cells[2].innerHTML){
alert('<#1846#>');
document.form.vpn_clientlist_commonname_0.focus();
document.form.vpn_clientlist_commonname_0.select();
return false;
}
}
}
do_addRow_Group();
}
function do_addRow_Group(){
addRowAdvanced(document.form.vpn_clientlist_commonname_0 ,1);
addRowAdvanced(document.form.vpn_clientlist_subnet_0, 0);
addRowAdvanced(document.form.vpn_clientlist_netmask_0, 0);
addRowAdvanced(document.form.vpn_clientlist_push_0, 0);
document.form.vpn_clientlist_push_0.value="0"; //reset selection
allowed_openvpn_clientlist();
}
function addRowAdvanced(obj, head){
if(head == 1)
openvpn_clientlist_array += "<1>";
else
openvpn_clientlist_array += ">";
openvpn_clientlist_array += obj.value;
obj.value = "";
}
function allowed_openvpn_clientlist(){
var openvpn_clientlist_row = openvpn_clientlist_array.split('<');
var code = "";
code +='<table width="100%" cellspacing="0" cellpadding="4" align="center" class="list_table" id="openvpn_clientlist_table">';
if(openvpn_clientlist_row.length == 1)
code +='<tr><td style="color:#FFCC00;" colspan="6"><#1802#></td>';
else{
for(var i = 1; i < openvpn_clientlist_row.length; i++){
code +='<tr id="row'+i+'">';
var openvpn_clientlist_col = openvpn_clientlist_row[i].split('>');
var wid=[0, 36, 20, 20, 12];
for (var j = 1; j < openvpn_clientlist_col.length; j++){
if (j == 4)
code +='<td width="'+wid[j]+'%">'+ ((openvpn_clientlist_col[j] == 1 || openvpn_clientlist_col[j] == 'Yes') ? 'Yes' : 'No') +'</td>';
else
code +='<td width="'+wid[j]+'%">'+ openvpn_clientlist_col[j] +'</td>';
}
code +='<td width="12%">';
code +='<input class="remove_btn" onclick="del_openvpnRow(this);" value=""/></td>';
}
}
code +='</table>';
document.getElementById("openvpn_clientlist_Block").innerHTML = code;
}
function del_openvpnRow(r) {
var i = r.parentNode.parentNode.rowIndex;
document.getElementById("openvpn_clientlist_table").deleteRow(i);
var openvpn_clientlist_value = "";
var rowLength = document.getElementById("openvpn_clientlist_table").rows.length;
for(var k = 0; k < rowLength; k += 1) {
for(var j = 0; j < document.getElementById("openvpn_clientlist_table").rows[k].cells.length - 1; j += 1){
if(j == 0)
openvpn_clientlist_value += "<1>";
else
openvpn_clientlist_value += ">";
openvpn_clientlist_value += document.getElementById("openvpn_clientlist_table").rows[k].cells[j].innerHTML;
}
}
openvpn_clientlist_array = openvpn_clientlist_value;
if(openvpn_clientlist_array == "")
allowed_openvpn_clientlist();
}
function cancel_Key_panel() {
this.FromObject ="0";
$("#tlsKey_panel").fadeOut(300);
}
function save_keys() {
if (openvpn_unit == "1") {
document.openvpnTLSKeyForm.vpn_crt_server1_ca.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_ca.value;
document.openvpnTLSKeyForm.vpn_crt_server1_crt.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_crt.value;
document.openvpnTLSKeyForm.vpn_crt_server1_key.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_key.value;
document.openvpnTLSKeyForm.vpn_crt_server1_dh.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_dh.value;
document.openvpnTLSKeyForm.vpn_crt_server1_crl.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_crl.value;
document.openvpnTLSKeyForm.vpn_crt_server1_static.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_static.value;
document.openvpnTLSKeyForm.vpn_crt_server1_extra.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_extra.value;
document.openvpnTLSKeyForm.vpn_crt_server1_static.disabled = false;
document.openvpnTLSKeyForm.vpn_crt_server1_ca.disabled = false;
document.openvpnTLSKeyForm.vpn_crt_server1_crt.disabled = false;
document.openvpnTLSKeyForm.vpn_crt_server1_key.disabled = false;
document.openvpnTLSKeyForm.vpn_crt_server1_dh.disabled = false;
document.openvpnTLSKeyForm.vpn_crt_server1_crl.disabled = false;
document.openvpnTLSKeyForm.vpn_crt_server1_extra.disabled = false;
} else {
document.openvpnTLSKeyForm.vpn_crt_server2_ca.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_ca.value;
document.openvpnTLSKeyForm.vpn_crt_server2_crt.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_crt.value;
document.openvpnTLSKeyForm.vpn_crt_server2_key.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_key.value;
document.openvpnTLSKeyForm.vpn_crt_server2_dh.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_dh.value;
document.openvpnTLSKeyForm.vpn_crt_server2_crl.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_crl.value;
document.openvpnTLSKeyForm.vpn_crt_server2_static.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_static.value;
document.openvpnTLSKeyForm.vpn_crt_server2_extra.value = document.openvpnTLSKeyForm.edit_vpn_crt_server_extra.value;
document.openvpnTLSKeyForm.vpn_crt_server2_static.disabled = false;
document.openvpnTLSKeyForm.vpn_crt_server2_ca.disabled = false;
document.openvpnTLSKeyForm.vpn_crt_server2_crt.disabled = false;
document.openvpnTLSKeyForm.vpn_crt_server2_key.disabled = false;
document.openvpnTLSKeyForm.vpn_crt_server2_dh.disabled = false;
document.openvpnTLSKeyForm.vpn_crt_server2_crl.disabled = false;
document.openvpnTLSKeyForm.vpn_crt_server2_extra.disabled = false;
}
document.openvpnTLSKeyForm.submit();
cancel_Key_panel();
}
/* Advanced Setting end */
function update_vpn_client_state() {
$.ajax({
url: '/ajax_openvpn_client_status.xml',
dataType: 'xml',
error: function(xml) {
setTimeout("update_vpn_client_state();", 1000);
},
success: function(xml) {
var vpnserverXML = xml.getElementsByTagName("vpnserver");
var client_status = vpnserverXML[0].firstChild.nodeValue;
parseOpenVPNClients(client_status);
openvpnd_connected_status();
setTimeout("update_vpn_client_state();", 3000);
}
});
}
function defaultSettings() {
if (confirm("WARNING: This will reset this OpenVPN server to factory default settings!\n\nKeys and certificates associated to this instance will also be DELETED!\n\nProceed?")) {
document.form.action_script.value = "stop_vpnserver" + openvpn_unit + ";clearvpnserver" + openvpn_unit;
enable_openvpn(0);
document.form.VPNServer_enable.value = "0";
parent.showLoading();
document.form.submit();
} else {
return false;
}
}
function enable_server_igncrt(flag){
if (getRadioValue(document.form.vpn_server_userpass_auth) == 0)
flag = 0;
document.form.vpn_server_crypt.style.display = (flag==1)?"none":"";
document.form.vpn_server_crypt.value = (flag==1)?"tls":"<% nvram_get("vpn_server_crypt"); %>";
update_visibility();
document.getElementById("Hint_fixed_tls_crypto").style.display = (flag==1)?"":"none";
document.getElementById("Fixed_tls_crypto").style.display = (flag==1)?"":"none";
document.getElementById("allowed_client_name").innerHTML = (flag==1)?"<#2709#>":"Common Name(CN)";
}
function vpnServerTlsKeysize(_obj) {
document.form.vpn_server_tls_keysize.value = _obj.value;
setRadioValue(document.form.vpn_server_tls_keysize_basic, _obj.value);
}
function update_cipher() {
$("#cipher_hint").css("display", "none");
var cipher = document.form.vpn_server_cipher.value;
if(cipher == "default")
$("#cipher_hint").css("display", "");
}
function update_digest() {
$("#digest_hint").css("display", "none");
var digest = document.form.vpn_server_digest.value;
if(digest == "MD5" || digest == "RSA-MD4")
$("#digest_hint").css("display", "");
}
function exportCert() {
location.href = 'server_ovpn.cert';
}
function selectImportFile() {
document.import_cert_form.import_cert_file.click();
}
function importCert() {
var import_file = document.import_cert_form.import_cert_file.value;
var import_subname = import_file.substring(import_file.indexOf('.') + 1);
if(import_subname != 'cert') {
alert("<#2380#>");
document.import_cert_form.import_cert_file.value = "";
return false;
}
showLoading();
document.import_cert_form.submit();
}
function callback_upload_cert(_flag) {
if(_flag) {
var waiting_time = parseInt(document.form.action_wait.value);
showLoading(waiting_time);
setTimeout(function(){location.reload();}, waiting_time*1000);
}
else {
alert("<#2367#>");
hideLoading();
}
}

setTimeout("show_winq_qrcode();", 100);
function show_winq_qrcode() {
	var vpns1 = '<% nvram_get("vpn_server1_state"); %>';
	var vpns2 = '<% nvram_get("vpn_server2_state"); %>';
	
	if (vpns1 == "1" || vpns2 == "1") {
		document.getElementById("qrcode").style.display = "block";
		var vpnasset;
		
		$.ajax({
			url:"winq/vpnasset.json", 
			dataType:"json",
			async:false,
			success:function(json) {
				vpnasset = json;
			}
		});
		
		var winq_notes = "";
		if (vpnasset) {
			var vpninfo = vpnasset['VPNINFO'];
			winq_notes = "Your VPN ( <span style='color:#FFCC00'>";
			
			if (vpninfo) {
				for (var i = 0; i < vpninfo.length; i++) {
					if (vpninfo[i].vpnfileName == "client1.ovpn") {
						winq_notes += "Server1 ";
					} else {
						winq_notes += "Server2 ";
					}
				}
			}
			
			winq_notes += "</span>) has been successfully registered on QLC Chain as a digital asset and start to Win QLC, Enjoy!";
		} else {
			winq_notes = "Open WinQ App on your phone, Click 'VPN->My Asserts->Add Asset' to register your asset and Start to earn QLC token.";
		}
		
		document.getElementById("winq_notes_open").innerHTML = winq_notes;
	} else {
		document.getElementById("winq_notes").innerHTML = "OpenVpn Server is not running, Configure the OpenVpn Server and Come back. <a style='font-weight: bolder;text-decoration:underline;' class='hyperlink' href='Advanced_VPN_OpenVPN.asp'>Configure VPN</a>";
	}
	
	setTimeout("show_winq_qrcode();", 1000);
}
</script>
</head>
<body onload="initial();">
<div id="tlsKey_panel" class="contentM_qis">
<table class="QISform_wireless" border=0 align="center" cellpadding="5" cellspacing="0">
<form method="post" name="openvpnTLSKeyForm" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="current_page" value="Advanced_VPN_OpenVPN.asp">
<input type="hidden" name="next_page" value="Advanced_VPN_OpenVPN.asp">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="flag" value="background">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_script" value="saveNvram">
<input type="hidden" name="action_wait" value="1">
<input type="hidden" name="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
<input type="hidden" name="vpn_crt_server1_ca" value="" disabled>
<input type="hidden" name="vpn_crt_server1_crt" value="" disabled>
<input type="hidden" name="vpn_crt_server1_key" value="" disabled>
<input type="hidden" name="vpn_crt_server1_dh" value="" disabled>
<input type="hidden" name="vpn_crt_server1_crl" value="" disabled>
<input type="hidden" name="vpn_crt_server1_extra" value="" disabled>
<input type="hidden" name="vpn_crt_server2_ca" value="" disabled>
<input type="hidden" name="vpn_crt_server2_crt" value="" disabled>
<input type="hidden" name="vpn_crt_server2_key" value="" disabled>
<input type="hidden" name="vpn_crt_server2_dh" value="" disabled>
<input type="hidden" name="vpn_crt_server2_crl" value="" disabled>
<input type="hidden" name="vpn_crt_server2_extra" value="" disabled>
<input type="hidden" name="vpn_crt_server1_static" value="" disabled>
<input type="hidden" name="vpn_crt_server2_static" value="" disabled>
<tr>
<div class="description_down"><#2779#></div>
</tr>
<tr>
<div style="margin-left:30px; margin-top:10px;">
<p><#2773#> <span style="color:#FFCC00;">----- BEGIN xxx ----- </span>/<span style="color:#FFCC00;"> ----- END xxx -----</span> <#2774#>
<p>Limit: 7999 characters per field
</div>
<div style="margin:5px;*margin-left:-5px;width: 730px; height: 2px;" class="splitLine"></div>
</tr>
<tr>
<td valign="top">
<table width="700px" border="0" cellpadding="4" cellspacing="0">
<tbody>
<tr>
<td valign="top">
<table width="100%" id="page1_tls" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
<tr>
<th><#2778#></th>
<td>
<textarea rows="8" class="textarea_ssh_table" id="edit_vpn_crt_server_static" spellcheck="false" name="edit_vpn_crt_server_static" cols="65" maxlength="7999"></textarea>
</td>
</tr>
<tr id="edit_tls1">
<th><#2771#></th>
<td>
<textarea rows="8" class="textarea_ssh_table" id="edit_vpn_crt_server_ca" spellcheck="false" name="edit_vpn_crt_server_ca" cols="65" maxlength="7999"></textarea>
</td>
</tr>
<tr id="edit_tls2">
<th><#2776#></th>
<td>
<textarea rows="8" class="textarea_ssh_table" id="edit_vpn_crt_server_crt" spellcheck="false" name="edit_vpn_crt_server_crt" cols="65" maxlength="7999"></textarea>
</td>
</tr>
<tr id="edit_tls3">
<th><#2777#></th>
<td>
<textarea rows="8" class="textarea_ssh_table" id="edit_vpn_crt_server_key" spellcheck="false" name="edit_vpn_crt_server_key" cols="65" maxlength="7999"></textarea>
</td>
</tr>
<tr id="edit_tls4">
<th><#2772#><br><br><i>(Enter "none" to disable)</i></th>
<td>
<textarea rows="8" class="textarea_ssh_table" id="edit_vpn_crt_server_dh" spellcheck="false" name="edit_vpn_crt_server_dh" cols="65" maxlength="7999"></textarea>
</td>
</tr>
<tr id="edit_tls5">
<th>Certificate Revocation List<br><br><i>(Optional)</i></th>
<td>
<textarea rows="8" class="textarea_ssh_table" id="edit_vpn_crt_server_crl" spellcheck="false" name="edit_vpn_crt_server_crl" cols="65" maxlength="7999"></textarea>
</td>
</tr>
<tr id="edit_tls6">
<th>Extra Chain Certificates<br><br><i>(Optional)</i></th>
<td>
<textarea rows="8" class="textarea_ssh_table" id="edit_vpn_crt_server_extra" spellcheck="false" name="edit_vpn_crt_server_extra" cols="65" maxlength="7999"></textarea>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<div style="margin-top:5px;width:100%;text-align:center;">
<input class="button_gen" type="button" onclick="cancel_Key_panel();" value="<#141#>">
<input class="button_gen" type="button" onclick="save_keys();" value="<#1258#>">
</div>
</td>
</tr>
</form>
</table>
</div>
<div id="TopBanner"></div>
<div id="Loading" class="popup_bg"></div>
<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>
<form method="post" name="form" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="current_page" value="Advanced_VPN_OpenVPN.asp">
<input type="hidden" name="next_page" value="Advanced_VPN_OpenVPN.asp">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_wait" value="15">
<input type="hidden" name="action_script" value="">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
<input type="hidden" name="VPNServer_enable" value="<% nvram_get("VPNServer_enable"); %>">
<input type="hidden" name="VPNServer_mode" value="<% nvram_get("VPNServer_mode"); %>">
<input type="hidden" name="vpn_serverx_clientlist" value="">
<input type="hidden" name="vpn_serverx_start" value="<% nvram_get("vpn_serverx_start"); %>">
<input type="hidden" name="vpn_server_ccd_val" value="">
<input type="hidden" name="vpn_server_tls_keysize" value="<% nvram_get("vpn_server_tls_keysize"); %>">
<input type="hidden" name="vpn_server_cust2" value="<% nvram_get("vpn_server_cust2"); %>">
<input type="hidden" name="vpn_server_cust21" value="<% nvram_get("vpn_server_cust21"); %>">
<input type="hidden" name="vpn_server_cust22" value="<% nvram_get("vpn_server_cust22"); %>">
<table class="content" align="center" cellpadding="0" cellspacing="0">
<tr>
<td width="17">&nbsp;</td>
<td valign="top" width="202">
<div id="mainMenu"></div>
<div id="subMenu"></div>
</td>
<td valign="top">
<div id="tabMenu" class="submenuBlock"></div>
<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
<tr>
<td valign="top" >
<table width="760px" border="0" cellpadding="4" cellspacing="0" class="FormTitle" id="FormTitle" >
<tbody>
<tr>
<td bgcolor="#4D595D" valign="top">
	<div>&nbsp;</div>
	<div class="formfonttitle">Register QR Code - WINQ Server</div>
	<div style="margin:10px 0 10px 5px;" class="splitLine"></div>
	<div class="formfontdesc">
		<p>
			WinQ server is used to work together with WinQ App to register a OpenVPN server <br>
			as a digital asset on QLC Chain and win QLC Token from the network service sharing.
		</p>
	</div>
	<div id="winq_notes" class="formfontdesc" style="color:#FFCC00;"></div>
	
	<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
		<thead>
			<tr>
				<td colspan="2">QR Code</td>
			</tr>
		</thead>
		<tr>
			<td>
			<div id="qrcode" style="display:none;">
				<img src="/winq/winq.png">
			</div>
			</td>
		</tr>
	</table>
	
	<div id="winq_notes_open" class="formfontdesc" style="margin-top:10px;"></div>
</td>
</tr>
</tbody>
</table>
</td>
</tr>
</table>
</td>
</tr>
</table>
</form>
<div id="mailSendPanelContainer" class="hiddenPanelContainer">
<div class="hiddenPanel">
<form method="post" name="mailSendForm" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_script" value="restart_sendmail">
<input type="hidden" name="action_wait" value="5">
<input type="hidden" name="flag" value="background">
<input type="hidden" name="PM_MAIL_SUBJECT" value="My ovpn file">
<input type="hidden" name="PM_MAIL_FILE" value="/www/client<% nvram_get("vpn_server_unit"); %>.ovpn">
<input type="hidden" name="PM_LETTER_CONTENT" value="Here is the ovpn file.">
<div class="panelTableTitle">
<div>Send</div>
<div style="margin:10px 0 10px 5px;height: 2px;width: 100%;padding:0;" class="splitLine"></div>
</div>
<table border=0 align="center" cellpadding="5" cellspacing="0" class="FormTable panelTable">
<tr>
<th>PM_MAIL_TARGET</th>
<td valign="top">
<input type="text" class="input_32_table" name="PM_MAIL_TARGET" value="" autocorrect="off" autocapitalize="off">
</td>
</tr>
</table>
<div class="panelSubmiter">
<input id="mailSendPannelCancel" class="button_gen" type="button" value="<#141#>">
<input id="mailSendPannelSubmiter" class="button_gen" type="button" value="Send">
<img id="mailSendLoadingIcon" style="margin-left:5px;display:none;" src="/images/InternetScan.gif">
<script>
document.getElementById("mailSendPannelCancel").onclick = function(){
$("#mailSendPanelContainer").fadeOut(300);
}
document.getElementById("mailSendPannelSubmiter").onclick = function(){
$("#mailSendLoadingIcon").fadeIn(200);
document.mailSendForm.submit();
setTimeout(function(){
document.mailSendForm.PM_MAIL_TARGET.value = "";
$("#mailSendLoadingIcon").fadeOut(200);
$("#mailSendPanelContainer").fadeOut(300);
}, document.mailSendForm.action_wait.value*1000);
}
</script>
</div>
</form>
</div>
</div>
<div id="mailConfigPanelContainer" class="hiddenPanelContainer">
<div class="hiddenPanel">
<form method="post" name="mailConfigForm" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_script" value="saveNvram">
<input type="hidden" name="action_wait" value="3">
<input type="hidden" name="PM_SMTP_SERVER" value="<% nvram_get("PM_SMTP_SERVER"); %>">
<input type="hidden" name="PM_SMTP_PORT" value="<% nvram_get("PM_SMTP_PORT"); %>">
<input type="hidden" name="PM_SMTP_AUTH_USER" value="<% nvram_get("PM_SMTP_AUTH_USER"); %>">
<input type="hidden" name="PM_SMTP_AUTH_PASS" value="<% nvram_get("PM_SMTP_AUTH_PASS"); %>">
<input type="hidden" name="PM_MY_NAME" value="<% nvram_get("PM_MY_NAME"); %>">
<input type="hidden" name="PM_MY_EMAIL" value="<% nvram_get("PM_MY_EMAIL"); %>">
<div class="panelTableTitle">
<div>Setup mail server</div>
<div style="margin:10px 0 10px 5px;height: 2px;width: 100%;padding:0;" class="splitLine"></div>
</div>
<table border=0 align="center" cellpadding="5" cellspacing="0" class="FormTable panelTable">
<tr>
<th>PM_SMTP_SERVER</th>
<td valign="top">
<select style="width:350px;" name="PM_SMTP_SERVER_TMP" class="input_option">
<option value="smtp.gmail.com" <% nvram_match( "PM_SMTP_SERVER", "smtp.gmail.com", "selected"); %>>Google Gmail</option>
</select>
<script>
var smtpList = new Array()
smtpList = [
{smtpServer: "smtp.gmail.com", smtpPort: "587", smtpDomain: "gmail.com"},
{end: 0}
];
document.mailConfigForm.PM_SMTP_SERVER_TMP.onchange = function(){
document.mailConfigForm.PM_SMTP_PORT_TMP.value = smtpList[this.selectedIndex].smtpPort;
document.mailConfigForm.PM_SMTP_AUTH_USER_TMP.value = "";
document.mailConfigForm.PM_SMTP_AUTH_PASS_TMP.value = "";
document.mailConfigForm.PM_MY_NAME_TMP.value = "";
document.mailConfigForm.PM_MY_EMAIL_TMP.value = "";
}
</script>
</td>
</tr>
<input type="hidden" name="PM_SMTP_PORT_TMP" value="<% nvram_get("PM_SMTP_PORT"); %>">
<tr>
<th>PM_SMTP_AUTH_USER</th>
<td valign="top">
<input type="text" class="input_32_table" name="PM_SMTP_AUTH_USER_TMP" value="<% nvram_get("PM_SMTP_AUTH_USER"); %>" autocorrect="off" autocapitalize="off">
<script>
document.mailConfigForm.PM_SMTP_AUTH_USER_TMP.onkeyup = function(){
document.mailConfigForm.PM_MY_NAME_TMP.value = this.value;
document.mailConfigForm.PM_MY_EMAIL_TMP.value = this.value + "@" + smtpList[document.mailConfigForm.PM_SMTP_SERVER_TMP.selectedIndex].smtpDomain;
}
</script>
</td>
</tr>
<tr>
<th>PM_SMTP_AUTH_PASS</th>
<td valign="top">
<input type="password" class="input_32_table" name="PM_SMTP_AUTH_PASS_TMP" maxlength="100" value="" autocorrect="off" autocapitalize="off">
</td>
</tr>
<tr>
<th>PM_MY_NAME (Optional)</th>
<td valign="top">
<input type="text" class="input_32_table" name="PM_MY_NAME_TMP" value="<% nvram_get("PM_MY_NAME"); %>" autocorrect="off" autocapitalize="off">
</td>
</tr>
<tr>
<th>PM_MY_EMAIL (Optional)</th>
<td valign="top">
<input type="text" class="input_32_table" name="PM_MY_EMAIL_TMP" value="<% nvram_get("PM_MY_EMAIL"); %>" autocorrect="off" autocapitalize="off">
</td>
</tr>
</table>
<div class="panelSubmiter">
<input id="mailConfigPannelCancel" class="button_gen" type="button" value="<#141#>">
<input id="mailConfigPannelSubmiter" class="button_gen" type="button" value="<#1258#>">
<img id="mailConfigLoadingIcon" style="margin-left:5px;display:none;" src="/images/InternetScan.gif">
<script>
document.getElementById("mailConfigPannelCancel").onclick = function(){
$("#mailConfigPanelContainer").fadeOut(300);
}
document.getElementById("mailConfigPannelSubmiter").onclick = function(){
document.mailConfigForm.PM_SMTP_SERVER.value = document.mailConfigForm.PM_SMTP_SERVER_TMP.value;
if (document.mailConfigForm.PM_SMTP_PORT_TMP.value == "")
document.mailConfigForm.PM_SMTP_PORT.value = smtpList[0].smtpPort;
else
document.mailConfigForm.PM_SMTP_PORT.value = document.mailConfigForm.PM_SMTP_PORT_TMP.value;
document.mailConfigForm.PM_SMTP_AUTH_USER.value = document.mailConfigForm.PM_SMTP_AUTH_USER_TMP.value;
document.mailConfigForm.PM_SMTP_AUTH_PASS.value = document.mailConfigForm.PM_SMTP_AUTH_PASS_TMP.value;
document.mailConfigForm.PM_MY_NAME.value = document.mailConfigForm.PM_MY_NAME_TMP.value;
document.mailConfigForm.PM_MY_EMAIL.value = document.mailConfigForm.PM_MY_EMAIL_TMP.value;
$("#mailConfigLoadingIcon").fadeIn(200);
document.mailConfigForm.submit();
setTimeout(function(){
$("#mailConfigLoadingIcon").fadeOut(200);
showMailPanel();
}, document.mailConfigForm.action_wait.value*1000);
}
</script>
</div>
</form>
</div>
</div>
<iframe name="hidden_import_cert_frame" id="hidden_import_cert_frame" src="" width="0" height="0" frameborder="0"></iframe>
<form method="post" name="import_cert_form" action="upload_server_ovpn_cert.cgi" target="hidden_import_cert_frame" enctype="multipart/form-data">
<input type="file" name="import_cert_file" style="display:none;" onchange="importCert();"/>
</form>
<div id="footer"></div>
</body>
</html>

