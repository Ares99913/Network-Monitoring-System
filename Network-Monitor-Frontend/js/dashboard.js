// Dashboard page logic
function setProgress(id, value) {

    const circle = document.getElementById(id);

    const radius = 60;
    const circumference = 2 * Math.PI * radius;

    const offset =
        circumference -
        (value / 100) * circumference;

    circle.style.strokeDasharray = circumference;
    circle.style.strokeDashoffset = offset;

    if (value >= 80) {
        circle.style.stroke = "#ef4444";
    }
    else if (value >= 60) {
        circle.style.stroke = "#f59e0b";
    }
    else {
        circle.style.stroke = "#22c55e";
    }
}

setProgress("cpuRing", 72);
setProgress("memoryRing", 64);
setProgress("networkRing", 88);