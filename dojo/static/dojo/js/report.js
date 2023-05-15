function generatePDF(){
var dynamicContent = document.getElementById("report").innerHTML;
 
    // Create a new jsPDF object
    var doc = new jsPDF();
 
    // Set the font size and line height for the document
    doc.setFontSize(12);
    doc.setLineHeightFactor(1.5);
 
    // Split the content into an array of lines
    var lines = doc.splitTextToSize(dynamicContent, doc.internal.pageSize.getWidth() - 20);
 
    // Add each line to the document
    for (var i = 0; i < lines.length; i++) {
      doc.text(lines[i], 10, 20 + (i * 10));
    }
 
    // Save the PDF
    doc.save('my-pdf-document.pdf');
}