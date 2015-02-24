### Usage:

* Write your own callable object(let's say, a function named **foo**) that is meant to calculate the trading decision.
* New a AutoTradeCLI object and assign your callable object to **onDecision** parameter of the constructor of this object
* Start the CLI program by running **runCLI** method of this object

### Requirements of your function

Your callable object that calculates the trading decision must meet the following requirements:

* The callable object must takes 2 parameters: the first one is an iterable object containing the most recent trades received, and the second one is the callback function.
* The callback function is the function that takes an iterable object containing your decision as its only parameter, send your decision to the server, and returns an iterable object containing the response of the server.
* The first element of the parameter of the callback function is the trade type, *buy_market*, *sell_market*, *buy*, *sell*. If trade type is *buy_market* or *sell_market*, the second element of the parameter is the price/amount, correspondingly; if trade type is *buy* or *sell*, the second element is the price while the third element is the amount
* The first element of the returning object of the callback function is a bool indicating whether the server responds a success or not. If the server responds a success, the second element will be a detailed dictionary containg two keys: *order_id* and *result*, indicating the response; If fails, the second element will be a string representing the errorcode returned by the server

### Sample program

    import autotradecli

    def _foo(input, startResponse):
        decision = ('buy_market', 89.64)
        response = startResponse(decision)
        print(response)

    cli = autotradecli.AutoTradeCLI(onDecision = _foo)
    cli.runCLI()

### Note

This program must run under python 3 and does not support python 2

This program uses the following open-source libraries, copying their source code directly into this project: 
* [WebSocket](https://github.com/liris/websocket-client)
* [KBHIT](http://home.wlu.edu/~levys/software/kbhit.py)

### License

This project is released under **GNU Lesser General Public License**, either version 3, or (at your option) any later version.
