docker run --name action_server -p 9999:19999 -v /scratch/log:/log -v /mount/dfs:/dfs -v /scratch/clearcase_view:/cc_view --net mynet -e no_proxy=selenium -e SELENIUM_SERVER=http://selenium:4444/wd/hub -d act:0.1

