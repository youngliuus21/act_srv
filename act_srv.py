from aiohttp import web
import socketio

sio = socketio.AsyncServer()
app = web.Application()
sio.attach(app)

async def index(request):
    """Serve the client-side application."""
    with open('res/index.html') as f:
        return web.Response(text=f.read(), content_type='text/html')
        
@sio.on('connect', namespace='/action')
def connect(sid, environ):
    print("connect ", sid)

@sio.on('dialog.act', namespace='/action')
async def message(sid, data):
    print("action name: ", data['name'], sid)
    ac1 = sio.emit('act.status', data={'text':'action status:'+data['name']}, room=sid, namespace='/action')
    ac2 = sio.emit('act.status', data={'result':'ok', 'done':True}, room=sid, namespace='/action')
    await ac1
    await ac2

@sio.on('disconnect', namespace='/action')
def disconnect(sid):
    print('disconnect ', sid)

app.router.add_static('/static', 'static')
app.router.add_get('/', index)

if __name__ == '__main__':
    web.run_app(app, port=19999)