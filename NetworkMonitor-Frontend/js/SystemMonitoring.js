function createChart(id, data, color){

    const ctx = document.getElementById(id);

    new Chart(ctx, {

        type: 'line',

        data: {

            labels: ['1','2','3','4','5','6','7'],

            datasets: [{
                data: data,
                borderColor: color,
                backgroundColor: color + '20',
                fill: true,
                tension: 0.45,
                borderWidth: 3,
                pointRadius: 0
            }]
        },

        options: {

            responsive: true,
            maintainAspectRatio: false,

            plugins:{
                legend:{
                    display:false
                }
            },

            scales:{

                x:{
                    grid:{
                        color:'rgba(255,255,255,0.05)'
                    },
                    ticks:{
                        color:'#64748b'
                    }
                },

                y:{
                    grid:{
                        color:'rgba(255,255,255,0.05)'
                    },
                    ticks:{
                        color:'#64748b'
                    }
                }

            }

        }

    });

}

createChart(
    'cpuChart',
    [2,5,3,8,4,3,0],
    '#38bdf8'
);

createChart(
    'ramChart',
    [10,12,11,14,13,13,13.5],
    '#22c55e'
);

createChart(
    'diskChart',
    [20,22,24,23,25,25.4,25.6],
    '#f97316'
);