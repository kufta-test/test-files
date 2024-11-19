const urlParams = new URLSearchParams(window.location.search);

const toUrl = urlParams.get('toURL');

const rlink = $('.js-redirect');

rlink.click(() => {

  window.open(toUrl);

});