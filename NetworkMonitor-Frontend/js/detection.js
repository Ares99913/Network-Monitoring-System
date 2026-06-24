document.querySelectorAll('.gauge').forEach(gauge => {
    const value = parseInt(gauge.dataset.value);
    const degree = value * 3.6;
    let color = '#22c55e';
    let glow = 'green-glow';
    if(value > 50 && value <= 75){
        color = '#f59e0b';
        glow = 'orange-glow';
    }
    if(value > 75){
        color = '#ef4444';
        glow = 'red-glow';
    }
    gauge.style.background =
    `conic-gradient(
        ${color} 0deg ${degree}deg,
        rgba(255,255,255,.08) ${degree}deg 360deg
    )`;
    gauge.classList.add(glow);
});