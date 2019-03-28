from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select
import re
import os
import os.path
import shutil
import string
import random
import subprocess

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
    
class MyDriver:
    def  __enter__(self):
        ff_profile = webdriver.FirefoxProfile()
        ff_profile.set_preference("network.proxy.type", 2);
        ff_profile.set_preference("network.proxy.autoconfig_url", "http://wpad/wpad.dat")

        driver = webdriver.Remote("http://slc12gzh.us.oracle.com:8444", 
                          browser_profile=ff_profile,
                          desired_capabilities=webdriver.DesiredCapabilities.FIREFOX.copy())
        driver.implicitly_wait(20) # seconds
        self.driver = driver
        return self.driver
    def __exit__(self, type, value, traceback):
        self.driver.close()
        
def Login(driver, bug_num, sso):
    #login
    driver.get("https://bug.oraclecorp.com/pls/bug/webbug_edit.edit_info_by_rptno?report_title=&rptno_count=1&pos=1&query_id=-1&rptno="+bug_num)
    
    WebDriverWait(driver, 10).until(EC.visibility_of_element_located((By.NAME, 'ssousername')))
    ele_username = driver.find_element_by_name('ssousername')
    ele_username.send_keys(sso['username'])
    driver.find_element_by_name('password').send_keys(sso['password'])

    driver.find_element_by_class_name('submit_btn').click()
    
def RetrieveInfo(driver):
    res_num = ''
    list = driver.find_elements_by_xpath("//*[contains(text(), 'Resolution ID (PSFT)')]/..")
    if list:
        ele_b = list[0]
        m = re.search('.(\d{6})', ele_b.get_attribute('innerHTML'))
        res_num = m.group(1)
    
    report_rel = driver.find_element_by_id('affected_release').get_attribute('value')
    
    bug_subject = driver.find_element_by_id('subject').get_attribute('value')
    
    return res_num, report_rel, bug_subject

def CheckInfo(driver, res_num, report_rel, bug_subject, callback):
    if (not res_num):
        return {'res':False, 'text':'Cannot find resolution ID'}
    
    m = re.search('^((POC-|_)\d{6}(-|_)(\d{2})).*$', bug_subject)
    if (not m):
        return {'res':False, 'text':'The bug subject should begin with: POC-' + res_num + '-0X Please update and retry.'}
    abs_txt = m.group(1)
    if (res_num not in bug_subject):
        return {'res':False, 'text':'The bug subject should begin with: POC-' + res_num + '-0X Please update and retry.'}
    if (not report_rel):
        return {'res':False, 'text':'Reported Release is empty, please fill and retry.'}
    
    m = re.search("(^\d{1}\.\d{2})", report_rel)
    report_rel = 'PeopleSoft PeopleTools ' + m.group(0)
    
    tgt_dir = 'p:\\pt\\poc_idda\\POC\\POC-{}'.format(res_num)
    tgt_name = 'p:\\pt\\poc_idda\\POC\\POC-{}\\{}.zip'.format(res_num, abs_txt)
    
    names = list()
    names.append('p:\\pt\\poc_idda\\POC\\POC_{}\\{}.zip'.format(res_num, abs_txt))
    names.append('p:\\pt\\poc_idda\\POC\\POC-{}\\{}\\{}.zip'.format(res_num, abs_txt, abs_txt.replace('-','_')))
    names.append('p:\\pt\\poc_idda\\POC\\{}\\{}.zip'.format(abs_txt, abs_txt))
    names.append('p:\\pt\\poc_idda\\POC\\{}.zip'.format(abs_txt, abs_txt))
    names.append('p:\\pt\\poc_idda\\POC\\{}.zip'.format(abs_txt.replace('-','_'), abs_txt))
    names.append('p:\\pt\\poc_idda\\POC\\{}.zip'.format(abs_txt.replace('_','-'), abs_txt))
    
    res = {'res': True, 'res_num':res_num, 'abs_txt':abs_txt, 'report_rel':report_rel, 'bug_subject':bug_subject, 'filename':tgt_name}
    if os.path.isfile(tgt_name):
        return res
    else:
        if not os.path.exists(tgt_dir):
            os.makedirs(tgt_dir)
            #print('>>> mkdirs {}'.format(tgt_dir))
        for fname in names:
            if os.path.isfile(fname):
                shutil.move(fname, tgt_name)
                callback({'text':'zip file moved from {} to {}'.format(fname, tgt_name)})
                return res
    
    names.append(tgt_name)
    return {'res':False, 'text':'Cannot find the POC file bye these locations ( ' + ','.join(names) + '), please check and retry.'}
    
def MalwareScan(filename, cb):
    resultfile = filename.replace('.zip', '.scanresults')
    cmd = 'Y:\\pt_admin\\PTAdm\\psmscan.py -w d:\\tmp -s {} -l {}'.format(filename, resultfile)
    cb({'text':'begin malware scan...'})
    cb({'text':cmd})
    res = subprocess.call(cmd, shell=True)
    cb({'text':'malware scan result:'+str(res)})
    
def TakeScreenShot(driver, filename):
    #take screen shot
    driver.save_screenshot(filename)
    
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
 
def POCBugCheck(data, callback):
    with MyDriver() as driver:
        try:
            callback({"text":'Login'})
            Login(driver, data['bug_number'], sso=data['sso'])
            callback({"text":'RetrieveInfo'})
            res_num, report_rel, bug_subject = RetrieveInfo(driver)
            callback({"text":'CheckInfo'})
            res = CheckInfo(driver, res_num, report_rel, bug_subject, callback)
            if (res['res'] == False):
                res['done'] = True;
                callback(res);
                return
                
            MalwareScan(res['filename'], callback)
            
            randfile = id_generator() +'.png'
            TakeScreenShot(driver, 'static/' + randfile)
            callback({'text':'Job done.','screen':randfile})

            res['done'] = True
            callback(res)
        except Exception as e:
            callback({'res':False, 'done':True, 'text':'Error:'+str(e)})
            
def perform(data, callback):
    param = data['parameters']
    param['sso'] = data['sso']
    POCBugCheck(param, callback)