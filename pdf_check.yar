rule PDF_check
{
  meta:
    author = "Swagto Patra(trailblazergt)"
    description = "This is a custom rule for identification of PDF files."
   strings:
    $start = "%PDF"
    $end = "%%EOF"
   condition"
     $start at 0 and $end
}
