from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select
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

        driver = webdriver.Remote("http://slc12gzh.us.oracle.com:8444", 
                          browser_profile=ff_profile,
                          desired_capabilities=webdriver.DesiredCapabilities.FIREFOX.copy())
        driver._is_remote = False #workaround, see https://stackoverflow.com/questions/42754877/cant-upload-file-using-selenium-with-python-post-post-session-b90ee4c1-ef51-4/42770761#42770761
        driver.implicitly_wait(20) # seconds
        self.driver = driver
        return self.driver
    def __exit__(self, type, value, traceback):
        self.driver.close()
        
def find_img_by_src(driver, src):
    images = driver.find_elements_by_tag_name('img')
    for image in images:
        if src in image.get_attribute('src'):
            return image
    return None

def find_img_by_attr(driver, attr, value):
    images = driver.find_elements_by_tag_name('img')
    for image in images:
        if value in image.get_attribute(attr):
            return image
    return None