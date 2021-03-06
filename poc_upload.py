from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import TimeoutException
from aru2bug import aru2bug
import string
import random
from datetime import date
import os.path
import traceback
import time
import asyncio

class MyDriver:
    def  __enter__(self):
        ff_profile = webdriver.FirefoxProfile()
        ff_profile.set_preference("network.proxy.type", 2);
        ff_profile.set_preference("network.proxy.autoconfig_url", "http://wpad/wpad.dat")

        driver = webdriver.Remote(os.environ['SELENIUM_SERVER'],
                          browser_profile=ff_profile,
                          desired_capabilities={
                              'browserName': 'firefox',
                              'javascriptEnabled': True
                          })
        driver._is_remote = False #workaround, see https://stackoverflow.com/questions/42754877/cant-upload-file-using-selenium-with-python-post-post-session-b90ee4c1-ef51-4/42770761#42770761
        driver.implicitly_wait(20) # seconds
        self.driver = driver
        return self.driver
    def __exit__(self, type, value, traceback):
        self.driver.quit()
        
def Login(driver, sso):
    #login
    driver.get("http://aru.us.oracle.com:8080/ARU/Login/get_form?navigation=button")
    
    WebDriverWait(driver, 10).until(EC.visibility_of_element_located((By.NAME, 'ssousername')))
    driver.find_element_by_name('ssousername').send_keys(sso['username'])
    driver.find_element_by_name('password').send_keys(sso['password'])

    driver.find_element_by_class_name('submit_btn').click()

def GoUploadPage(driver):
    #goto upload page
    driver.get("http://aru.us.oracle.com:8030/upload_main.html")
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='WebAppBody']"))

    select = Select(driver.find_element_by_name('go'))
    select.select_by_visible_text('Upload a Patch')
    driver.find_element_by_id('btn_Go').click()

def FillUploadSelectionForm(driver, bug_num, rel):
    #upload selection form
    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='WebAppBody']"))
    WebDriverWait(driver, 10).until(EC.visibility_of_element_located((By.NAME, 'bug')))
    driver.find_element_by_name('bug').send_keys(bug_num)

    select = Select(driver.find_element_by_name('product'))
    select.select_by_value('21918')

    select = Select(driver.find_element_by_name('release'))
    select.select_by_visible_text(rel)

    select = Select(driver.find_element_by_name('plat_lang'))
    select.select_by_value('2000P')

    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='WebAppNavigate']"))
    driver.find_element_by_id('btn_Continue').click()
    
def FillUploadMetaForm(driver, abs_txt, date_value):
    #upload metadata form
    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='WebAppBody']"))
    driver.find_element_by_name('abstract').clear()
    driver.find_element_by_name('abstract').send_keys(abs_txt)
    select = Select(driver.find_element_by_name('dist_type'))
    select.select_by_value('By Development')

    driver.find_element_by_name('released_date').clear()
    driver.find_element_by_name('released_date').send_keys(date_value)
    driver.find_element_by_name('modified_date').clear()
    driver.find_element_by_name('modified_date').send_keys(date_value)

    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='WebAppNavigate']"))
    driver.find_element_by_id('btn_Continue').click()
    
def UploadLocationForm(driver, filename):
    #Upload Location Form
    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='WebAppBody']"))

    WebDriverWait(driver, 20).until(EC.visibility_of_element_located((By.NAME, 'xferfile')))
    driver.find_element_by_name('xferfile').send_keys(filename)  #local file only
    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='WebAppNavigate']"))
    driver.find_element_by_id('btn_Continue').click()

def FileContent(driver):
    #file content may wrong
    #driver.switch_to.default_content()

    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='WebAppBody']"))

    print('wait for comment visibility')
    WebDriverWait(driver, 20).until(EC.visibility_of_element_located((By.NAME, 'comment')))
    driver.find_element_by_name('comment').send_keys('upload poc')

    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='WebAppNavigate']"))
    driver.find_element_by_id('btn_Continue').click()
    
def SummaryForm(driver):
    #Upload Summary Form
    #check summary here
    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='WebAppNavigate']"))
    driver.find_element_by_id('btn_Commit').click()

def Confirm(driver):
    alert = driver.switch_to_alert()
    alert.accept()
    
def WaitBeforeLastScreen(driver):
    driver.switch_to.default_content()
    try:
        WebDriverWait(driver, 20).until(EC.frame_to_be_available_and_switch_to_it((By.NAME, 'WebAppBody')))
    except TimeoutException:
        print('WaitBeforeLastScreen does not found target frame.')
    #WebDriverWait(driver, 20).until(EC.visibility_of_element_located(By.XPATH, '//a[contains(@href, "process_form?aru=")]'))
    #await asyncio.sleep(5)
def TakeScreenShot(driver, filename):
    #take screen shot
    driver.save_screenshot(filename)
    
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def UploadPOC(data, callback):
    with MyDriver() as driver:
        try:
            callback({'text':'Start Upload POC'})
            callback({"text":'Login'})
            Login(driver, data['sso'])
            callback({"text":'GoUploadPage'})
            GoUploadPage(driver)
            callback({"text":'FillUploadSelectionForm'})
            FillUploadSelectionForm(driver, bug_num=data['bug_num'], rel=data['report_rel'])
            callback({"text":'FillUploadMetaForm'})
            date_str = date.today().strftime("%b-%d-%Y 00:00:00").upper()
            FillUploadMetaForm(driver, abs_txt=data['abs_txt'], date_value=date_str)
            callback({"text":"UploadLocationForm"})
            filename = data['filename']
            UploadLocationForm(driver, filename)
            callback({"text":"FileContent"})
            FileContent(driver)
            callback({"text":"SummaryForm"})
            SummaryForm(driver)
            callback({"text":"Confirm"})
            Confirm(driver)
            WaitBeforeLastScreen(driver)
            randfile = id_generator() +'.png'
            TakeScreenShot(driver, 'static/' + randfile)
            callback({'text':'POC uploaded.','screen':randfile})
            
            aru2bug(sso=data['sso'], bug_num=data['bug_num'], callback=callback, driver=driver)
            callback({'text':'Job done.'})
            
        except Exception as e:
            traceback.print_exc()
            randfile = id_generator() +'.png'
            TakeScreenShot(driver, 'static/' + randfile)
            callback({'text':'Job Error:'+str(e),'screen':randfile})
            
def perform(data, callback):
    param = data['parameters']['bug_info']
    param['bug_num'] = data['parameters']['bug_number']
    param['sso'] = data['sso']
    UploadPOC(param, callback)