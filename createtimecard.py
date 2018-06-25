from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

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
    driver.get("https://global-ebusiness.oraclecorp.com/OA_HTML/AppsLogin")
    WebDriverWait(driver, 10).until(EC.visibility_of_element_located((By.NAME, 'ssousername')))
    ele_username = driver.find_element_by_name('ssousername')
    ele_username.send_keys(sso['username'])
    driver.find_element_by_name('password').send_keys(sso['password'])

    driver.find_element_by_class_name('submit_btn').click()
    
def Nav1(driver):
    #nav 
    driver.find_element_by_link_text('CN BDC Employee Self Service').click()
    driver.find_element_by_link_text('Create Timecard').click()

def FillForm1(driver):
    #fill the form
    from selenium.webdriver.support.ui import Select
    select = Select(driver.find_element_by_name('A221N1'))
    select.select_by_visible_text('Vacation in Days')
    #driver.find_element_by_name('B21_1_4').send_keys('1')
    #driver.find_element_by_name('B21_1_5').send_keys('1')
    driver.find_element_by_name('B21_1_6').send_keys('1')
    driver.find_element_by_id('review_uixr').click()

def TakeScreenShot(driver, filename):
    #take screen shot
    driver.save_screenshot(filename)
    
import string
import random
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

async def CreateTimeCard(data, callback):
    with MyDriver() as driver:
        try:
            print('Start Create Time Card')
            Login(driver, sso=data['sso'])
            await callback({"text":'Login done.'})
            Nav1(driver)
            await callback({'text':'Nav done.'})
            FillForm1(driver)
            await callback({'text':'Fill Form done.'})
            
            randfile = id_generator() +'.png'
            TakeScreenShot(driver, 'static/' + randfile)
            await callback({'text':'Job done.','screen':randfile})

        except Exception as e:
            await callback({'text':'Error:'+str(e)})

async def perform(data, callback):
    await CreateTimeCard(data, callback)
    
if __name__ == "__main__":
    def testCallback(res):
        print(res['text'])
        
    perform({}, testCallback)