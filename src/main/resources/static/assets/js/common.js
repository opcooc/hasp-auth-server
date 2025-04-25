function openWindow(url, width, height) {
    window.removeEventListener('message', this.handleMessage, false);
    window.addEventListener('message', this.handleMessage, false);

    const left = window.innerWidth / 2 - width / 2;
    const top = window.innerHeight / 2 - height / 2;

    const options = `width=${width},height=${height},top=${top},left=${left}`;
    window.open(url, 'windowName', options);
}

function handleMessage(e) {
    console.log(e)
    if (e.origin !== window.location.origin) {
        return;
    }
    console.log(e)
    document.federation_form.submit();

}