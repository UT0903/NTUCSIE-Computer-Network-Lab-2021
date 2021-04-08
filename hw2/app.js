const express = require("express");
const bodyParser = require("body-parser");
const { spawn } = require('child_process');
const { exec } = require('child_process');
const readline = require('readline');
const iptables = require('iptables');
let app = express();
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/monitor", (req, res) => {
    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    let monitor_ip = ip.split(":")[3];
    console.log(`${monitor_ip} using monitor`);
    iptables.list('FORWARD', (rules) => {
        //console.log(rules);
        const myMap = {};
        for(let i = 0; i < rules.length; i++){
            if(rules[i].parsed.src !== '0.0.0.0/0'){
                if(myMap[rules[i].parsed.src] == null){
                    myMap[rules[i].parsed.src] = {};
                }
                myMap[rules[i].parsed.src]['upkt'] = rules[i].parsed.packets;
                myMap[rules[i].parsed.src]['ubyte'] = rules[i].parsed.bytes;
            }
            else if(rules[i].parsed.dst !== '0.0.0.0/0'){
                if(myMap[rules[i].parsed.dst] == null){
                    myMap[rules[i].parsed.dst] = {};
                }
                myMap[rules[i].parsed.dst]['dpkt'] = rules[i].parsed.packets;
                myMap[rules[i].parsed.dst]['dbyte'] = rules[i].parsed.bytes;
            }
        }
        retStr = `<table border="1">
                    <tr>
                        <th>IP</th>
                        <th>upload packets</th>
                        <th>upload bytes</th>
                        <th>download packets</th>
                        <th>download bytes</th>
                    </tr>`
        //console.log(myMap);
        for (let key in myMap) {
            //console.log(key);
            if(!key.includes("/")){
                retStr += `<tr>
                        <td>${key}</td>
                        <td>${myMap[key]['upkt']}</td>
                        <td>${myMap[key]['ubyte']}</td>
                        <td>${myMap[key]['dpkt']}</td>
                        <td>${myMap[key]['dbyte']}</td>
                    </tr>`
            }
        }
        retStr += `</table><br/>
            <form action="block" method="post">
                <label for="IP">IP to BAN:</label>
                <input type="text" name="IP">
                <button>GO!</button>
            </form>`
        res.setHeader("Context-type", "text/html");
        res.send(retStr);
    })
});
app.post('/block', (req, res) =>{
    let delete_ip = req.body.IP;
    spawn("iptables", ["-t", "nat", "-D", "PREROUTING", "-s", delete_ip, "-j", "ACCEPT"]);
    spawn("iptables", ["-t", "nat", "-D", "PREROUTING", "-d", delete_ip, "-j", "ACCEPT"]);
    spawn("iptables", ["-D", "FORWARD", "-s", delete_ip, "-j", "ACCEPT"]);
    spawn("iptables", ["-D", "FORWARD", "-d", delete_ip, "-j", "ACCEPT"]);
    console.log(`delete IP: ${delete_ip}`)
});
app.get(/\/*/, (req, res) => {
    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    let remote_ip = ip.split(":")[3];
    console.log(`${remote_ip} is asking for wifi!`);
    res.setHeader("Context-type", "text/html")
    res.send(`
        <html>
            <div>P kid's home</div>
            <form action="login" method="post">
                name: <input type="text" name="name" />
                </br>
                password: <input type="password" name="password" />
                </br>
                <button>GO!</button>
            </form>
        </html>`
    );
});

app.post("/login", (req, res) => {
    console.log(req.body)
    let name = req.body.name;
    let password = req.body.password;
    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    let remote_ip = ip.split(":")[3];
    console.log(remote_ip)
    if (name == "cnlab" && password == "pkid") {
        console.log(`${remote_ip}login success`);
        res.send("<h1> Login success </h1>");
        //TODO
        spawn("iptables", ["-t", "nat", "-I", "PREROUTING", "1", "-s", remote_ip, "-j", "ACCEPT"]);
        spawn("iptables", ["-t", "nat", "-I", "PREROUTING", "1", "-d", remote_ip, "-j", "ACCEPT"]);
        spawn("iptables", ["-I", "FORWARD", "-s", remote_ip, "-j", "ACCEPT"]);
        spawn("iptables", ["-I", "FORWARD", "-d", remote_ip, "-j", "ACCEPT"]);
        //res.redirect("/monitor");

    } else {
        console.log(remote_ip, 'login error')
        res.send("<h1>Error</h1>");
        //spawn("iptables", ["-t", "nat","-I", "PREROUTING", "1", "-s", remote_ip, "-j", "DROP"]);
        //spawn("iptables", ["-t", "nat", "-I", "PREROUTING", "1", "-d", remote_ip, "-j", "DROP"]);
        //spawn("iptables", ["-I", "FORWARD", "-s", remote_ip, "-j", "DROP"]);
        //spawn("iptables", ["-I", "FORWARD", "-d", remote_ip, "-j", "DROP"]);
        //res.redirect("/login");
    }
});


app.listen(9090);
console.log("Start listening!")
