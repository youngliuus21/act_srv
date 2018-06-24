from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select
import string
import random
from datetime import date

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
        
def Login(driver, sso):
    #login
    with open('C:\\Users\\yanliu\\Documents\\test2.txt') as f:
        ps = f.read()
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
    
def UploadLocationForm(driver, file_path):
    #Upload Location Form
    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='WebAppBody']"))

    driver.find_element_by_name('xferfile').send_keys(file_path)  #local file only
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
	driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='WebAppBody']"))
	WebDriverWait(driver, 20).until(EC.visibility_of_element_located(By.XPATH, '//a[contains(@href, "process_form?aru=")]'))
def TakeScreenShot(driver, filename):
    #take screen shot
    driver.save_screenshot(filename)
    
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

async def UploadPOC(data, callback):
    with MyDriver() as driver:
        try:
            await callback({'text':'Start Upload POC'})
            await callback({"text":'Login'})
            Login(driver, data['sso'])
            await callback({"text":'GoUploadPage'})
            GoUploadPage(driver)
            await callback({"text":'FillUploadSelectionForm'})
            FillUploadSelectionForm(driver, bug_num=data['bug_num'], rel=data['report_rel'])
            await callback({"text":'FillUploadMetaForm'})
            date_str = date.today().strftime("%b-%d-%y 00:00:00").upper()
            FillUploadMetaForm(driver, abs_txt=data['abs_txt'], date_value=date_str)
            await callback({"text":"UploadLocationForm"})
            UploadLocationForm(driver, data['filename'])
            await callback({"text":"FileContent"})
            FileContent(driver)
            await callback({"text":"SummaryForm"})
            SummaryForm(driver)
            await callback({"text":"Confirm"})
            Confirm(driver)
            WaitBeforeLastScreen(driver)
            randfile = 'static/' + id_generator() +'.png'
            TakeScreenShot(driver, randfile)
            await callback({'text':'Job done.','screen':randfile})
        except Exception as e:
            randfile = 'static/' + id_generator() +'.png'
            TakeScreenShot(driver, randfile)
            await callback({'text':'Job Error:'+str(e),'screen':randfile})
            
async def perform(data, callback):
    param = data['parameters']['bug_info']
    param['bug_num'] = data['parameters']['bug_number']
    param['sso'] = data['sso']
    await UploadPOC(param, callback)