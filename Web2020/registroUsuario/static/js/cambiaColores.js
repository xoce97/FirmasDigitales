(function() {
    window.onload = function() {
        var id = setInterval(function() {
            var contador = 0;
            var a=Math.floor(Math.random() * 255);
            var b=Math.floor(Math.random() * 255);
            var c=Math.floor(Math.random() * 255);
	        document.body.style.backgroundColor = 'rgb(' + a + ',' + b + ',' + c + ')';
        }, 1000);

        var boton = document.getElementById("botonDetener");
	    boton.onclick = function() {
	        clearInterval(id);
        }
        
    }




})();