import axios from 'axios'
require('dotenv').config()

axios.post('/api/token/token', JSON.stringify({
    key: 'aaaaaa'
})).then(res => {
    // ruleid: hardcoded-bearer-token
    axios.defaults.headers.common['Authorization'] = process.env.TOKEN;


}).catch((error) => {
    console.error(error)
});

console.log("adding this for no reason")
