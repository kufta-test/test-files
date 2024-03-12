import axios from 'axios'
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

axios.post('/api/token', JSON.stringify({
    key: 'aaaaaa'
})).then(res => {
    // ruleid: hardcoded-bearer-token
    axios.defaults.headers.common['Authorization'] = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // ruleid: hardcoded-bearer-token
    axios.defaults.headers.common['Authorization'] = "Bearer "+token;


    // ok: hardcoded-bearer-token
    axios.defaults.headers.common['Authorization'] = "Bearer eexample";


    // ok: hardcoded-bearer-token
    axios.defaults.headers.common['Authorization'] = "Bearer" + config.value["token"]


}).catch((error) => {
    console.error(error)
});