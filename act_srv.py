from aiohttp import web
import socketio
import importlib
import asyncio
from functools import partial
from concurrent.futures import ThreadPoolExecutor

sio = socketio.AsyncServer()
app = web.Application()
sio.attach(app)

async def index(request):
    """Serve the client-side application."""
#    with open('res/index.html') as f:
#        return web.Response(text=f.read(), content_type='text/html')
        
@sio.on('connect', namespace='/action')
def connect(sid, environ):
    print("connect ", sid)

act_executor = ThreadPoolExecutor()

@sio.on('dialog.act', namespace='/action')
async def message(sid, data):
    print("action name: ", data['name'], sid)
       
    def callback(res):
        app.loop.create_task(sio.emit('act.status', data=res, room=sid, namespace='/action'))
        
    callback({'text':'action begin:'+data['name']})

    module = importlib.import_module(data['name'].lower())
    """in case I changed the module"""
    module = importlib.reload(module)
    
    def closesocket():
        callback({'result':'ok', 'close':True})
    def action1():
        module.perform(data, callback)
        print('schedule close socket')
        app.loop.call_later(30, closesocket)
        
    app.loop.run_in_executor(act_executor, action1)
    

        
    

@sio.on('disconnect', namespace='/action')
def disconnect(sid):
    print('disconnect ', sid)

app.router.add_static('/static', 'static')
app.router.add_get('/', index)

if __name__ == '__main__':
    web.run_app(app, port=19999)