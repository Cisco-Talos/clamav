/*****************************************************************************
 ** Name:        wxwidgets.js
 ** Purpose:     The wxWidgets documentation javascript
 ** Author:      Doxygen team
 ** RCS-ID:      $Id$
 ** Licence:     wxWindows licence
 *****************************************************************************/

// from w3schools
function getCookie(c_name)
{
  if (document.cookie.length>0)
  {
    c_start=document.cookie.indexOf(c_name + "=");
    if (c_start!=-1)
    {
      c_start=c_start + c_name.length+1;
      c_end=document.cookie.indexOf(";",c_start);
      if (c_end==-1) c_end=document.cookie.length;
      return unescape(document.cookie.substring(c_start,c_end));
    }
  }
  return "";
}
// from w3schools
function setCookie(c_name,value,expiredays)
{
  var exdate=new Date();
  exdate.setDate(exdate.getDate()+expiredays);
  document.cookie=c_name+ '=' +escape(value)+
  ((expiredays==null) ? '' : ';expires='+exdate.toGMTString());
}

// Reimplementation of changeDisplayState
function mychangeDisplayState( e )
{
  var num=this.id.replace(/[^[0-9]/g,'');
  var button=this.firstChild;
  var sectionDiv=document.getElementById('dynsection'+num);
  if (sectionDiv.style.display=='none'||sectionDiv.style.display==''){
    sectionDiv.style.display='block';
    button.src='open.gif';
  }else{
    sectionDiv.style.display='none';
    button.src='closed.gif';
  }

  setCookie( 'sectionDiv.style.display', sectionDiv.style.display );

}

window.onload = function myinitDynSections()
{
  var divs=document.getElementsByTagName('div');
  var sectionCounter=1;
  for(var i=0;i<divs.length-1;i++){
    if(divs[i].className=='dynheader'&&divs[i+1].className=='dynsection'){
      var header=divs[i];
      var section=divs[i+1];
      var button=header.firstChild;
      if (button!='IMG'){
        divs[i].insertBefore(document.createTextNode(' '),divs[i].firstChild);
        button=document.createElement('img');
        divs[i].insertBefore(button,divs[i].firstChild);
      }
      header.style.cursor='pointer';
      header.onclick=mychangeDisplayState;
      header.id='dynheader'+sectionCounter;
      section.id='dynsection'+sectionCounter;

      var display = getCookie( 'sectionDiv.style.display' );
      if ( display == '' || display == 'block' ){
        section.style.display='block'; // default
        button.src='open.gif';
      }else{
        section.style.display='none';
        button.src='closed.gif';
      }
      setCookie( 'sectionDiv.style.display', section.style.display );

      section.style.marginLeft='14px';
      sectionCounter++;
    }
  }
}
