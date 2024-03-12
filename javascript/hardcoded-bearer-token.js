import axios from 'axios'
require('dotenv').config()

axios.post('/api/token', JSON.stringify({
    key: 'aaaaaa'
})).then(res => {
    // ruleid: hardcoded-bearer-token
    axios.defaults.headers.common['Authorization'] = process.env.TOKEN;

    // ruleid: hardcoded-bearer-token
    axios.defaults.headers.common['Authorization'] = process.env.TOKEN;


    // ok: hardcoded-bearer-token
    axios.defaults.headers.common['Authorization'] = "Bearer eexample";

    // ok: hardcoded-bearer-token
    axios.defaults.headers.common['Authorization'] = "Bearer" + config.value["token"]


}).catch((error) => {
    console.error(error)
});