from act_base import MyDriver
from act_base import find_img_by_src
from act_base import find_img_by_attr
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import urllib

def openbug(driver, bug_num, sso):
    #login
    driver.get("https://bug.oraclecorp.com/pls/bug/webbug_edit.edit_info_by_rptno?report_title=&rptno_count=1&pos=1&query_id=-1&rptno="+bug_num)
    
    try:
        WebDriverWait(driver, 10).until(EC.visibility_of_element_located((By.NAME, 'ssousername')))
        ele_username = driver.find_element_by_name('ssousername')
        ele_username.send_keys(sso['username'])
        driver.find_element_by_name('password').send_keys(sso['password'])

        driver.find_element_by_class_name('submit_btn').click()
    except TimeoutException:
            print('does not find login info, already login?')
            
def Login_url(driver, url, sso):
    #login
    driver.get(url)
    
    try:
        WebDriverWait(driver, 5).until(EC.visibility_of_element_located((By.NAME, 'ssousername')))
        ele_username = driver.find_element_by_name('ssousername')
        ele_username.send_keys(sso['username'])
        driver.find_element_by_name('password').send_keys(sso['password'])
        driver.find_element_by_class_name('submit_btn').click()
    except TimeoutException:
            print('does not find login info, already login?')
    
def get_aru_info(driver):
    for i in range(24):
        try:
            WebDriverWait(driver, 10).until(EC.visibility_of_element_located((By.PARTIAL_LINK_TEXT, 'ARU ')))
            links = driver.find_elements(By.PARTIAL_LINK_TEXT, 'ARU ') # we need to get the last one...
            link = links[-1]
            href = link.get_attribute('href')
            return href
        except TimeoutException:
            print('let us try again to look for aru link...')
            driver.refresh()
       
def open_aru(driver, arulink, sso):
    #Login_url(driver, 'http://aru.us.oracle.com:8080/ARU/Login/get_form?navigation=button', sso)
    driver.get('http://aru.us.oracle.com:8080/ARU/Login/get_form?navigation=button')
    driver.get(arulink)
    
    img = find_img_by_src(driver, '/images/mail.gif')
    link = img.find_element_by_xpath('..')
    
    href = link.get_attribute('href')
    txt = urllib.parse.unquote(href, 'utf-8')
    
    ind1 = txt.index('Dear Customer')
    return txt[ind1:]
    

def update_bug(driver, bug_num, sso, txt):
    url = 'https://bug.oraclecorp.com/pls/bug/webbug_edit.edit_info_top?rptno=' + bug_num
    driver.get(url)
    #Login_url(driver, url, sso)
    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='bugframe']"))
    
    txtarea = driver.find_element_by_name('bug_desc')
    txtarea.send_keys(txt)
    
    driver.find_element_by_name('hide_added').click()
    
    driver.switch_to.default_content()
    driver.switch_to.frame(driver.find_element_by_css_selector("frame[name='LINKS']"))
    
    img = find_img_by_attr(driver, 'alt', 'Save Changes')
    link = img.find_element_by_xpath('..')
    link.click()       
    
def aru2bug_internal(driver, sso, bug_num, callback):
    openbug(driver, bug_num, sso)
    aru_link = get_aru_info(driver)
    print(aru_link)
    callback({"text":"get aru info"})
    txt = open_aru(driver, aru_link, sso)
    print(txt)
    update_bug(driver, bug_num, sso, txt)
    callback({"text":"update bug with aru info"})

def aru2bug(sso, bug_num, callback, driver):
    if driver:
        aru2bug_internal(driver, sso, bug_num, callback)
    else:
        with MyDriver() as driver:
            aru2bug_internal(driver, sso, bug_num, callback)
        