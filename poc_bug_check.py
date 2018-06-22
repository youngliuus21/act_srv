from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select
import re
import os.path
import string
import random

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

def CheckInfo(driver, res_num, report_rel, bug_subject):
    if (not res_num):
        return {'res':False, 'text':'Cannot find resolution ID'}
    
    m = re.search('^((POC-|_)\d{6}(-|_)(\d{2})).*$', bug_subject)
    if (not m):
        return {'res':False, 'text':'The bug subject should begin with: POC-' + res_num + '-XX... Please update and retry.'}
    abs_txt = m.group(1)
    if (res_num not in bug_subject):
        return {'res':False, 'text':'The bug subject should begin with: POC-' + res_num + '-XX... Please update and retry.'}
    if (not report_rel):
        return {'res':False, 'text':'Reported Release is empty, please fill and retry.'}
    
    m = re.search("(^\d{1}\.\d{2})", report_rel)
    report_rel = 'PeopleSoft PeopleTools ' + m.group(0)
    
    filename = 'p:\\pt\\poc_idda\\POC\\POC-{}\\{}.zip'.format(res_num, abs_txt)
    if not os.path.isfile(filename):
        return {'res':False, 'text':'Cannot find file ' + filename + ', please check and retry.'}
    
    return {'res': True, 'res_num':res_num, 'abs_txt':abs_txt, 'report_rel':report_rel, 'bug_subject':bug_subject, 'filename':filename}
    
async def POCBugCheck(data, callback):
    with MyDriver() as driver:
        try:
            await callback({"text":'Login'})
            Login(driver, data['bug_number'], sso=data['sso'])
            await callback({"text":'RetrieveInfo'})
            res_num, report_rel, bug_subject = RetrieveInfo(driver)
            await callback({"text":'CheckInfo'})
            res = CheckInfo(driver, res_num, report_rel, bug_subject)
            res['done'] = True
            await callback(res)
        except Exception as e:
            await callback({'text':'Error:'+str(e)})
            
async def perform(data, callback):
    await POCBugCheck(data['parameters'], callback)