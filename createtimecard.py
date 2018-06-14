from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary

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

def Login(driver):
    #login
    driver.get("https://global-ebusiness.oraclecorp.com/OA_HTML/AppsLogin")
    #with open('C:\\Users\\yanliu\\Documents\\test2.txt') as f:
    #    ps = f.read()
    ele_username = driver.find_element_by_name('ssousername')
    ele_username.send_keys(name)
    driver.find_element_by_name('password').send_keys(ps)

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
    driver.find_element_by_name('B21_1_4').send_keys('1')
    driver.find_element_by_name('B21_1_5').send_keys('1')
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
    print('test0.1')
    with MyDriver() as driver:
        try:
            
            print('test1')
            c1 = callback({'text':'Start Create Time Card'})
            Login(driver)
            c2 = callback({"text":'Login done.'})
            Nav1(driver)
            c3 = callback({'text':'Nav done.'})
            FillForm1(driver)
            c4 = callback({'text':'FillForm done.'})
            
            randfile = 'static/' + id_generator() +'.png'
            TakeScreenShot(driver, randfile)
            c5 = callback({'text':'Job done.','screen':randfile})
            await c1
            await c2
            await c3
            await c4
            await c5
        except Exception as e:
            await callback({'text':'Error:'+str(e)})

async def perform(data, callback):
    params = data['parameters']
    #c1 = callback({'status':True, 'text':'Module Action Status, begin_date:'+params['begin_date']+', end_date:'+params['end_date']})
    #c2 = callback({'result':'ok', 'done':True})
    await CreateTimeCard(data, callback)
    
if __name__ == "__main__":
    def testCallback(res):
        print(res['text'])
        
    perform({}, testCallback)