console.log("test");

$(document).ready(function(){
    $("#notification-modal").modal("show")
    $("#search-rule-input").on("keyup", function() {
        var value = $(this).val().toLowerCase();
        $("#rule-table tr").filter(function() {
        $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
    });
});
