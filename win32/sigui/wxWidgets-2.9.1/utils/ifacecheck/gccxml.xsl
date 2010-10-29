<?xml version="1.0"?>

<!-- This file was taken from http://www.gccxml.org
     where it was contributed by Ivan Kissiov.

     This is useful to 'see' the structure of the gccXML output.
     Usage:

        xsltproc gccxml.xsl file_created_by_gccxml.xml
-->

<xsl:stylesheet
        xmlns:xsl = "http://www.w3.org/1999/XSL/Transform"
        version = "1.0">
    <xsl:output method="html"/>

    <xsl:template match = "GCC_XML">

	<!-- =============================================== -->
    <html>
    <table border="0">
		<tr><td>A</td><td ><a href="#TA">Array Types</a></td></tr>
		<tr><td>B</td><td ><a href="#TB">Builtins</a></td></tr>
		<tr><td>Co</td><td ><a href="#TC">Constructors</a></td></tr>
		<tr><td>Cvt</td><td ><a href="#TCT">Converter</a></td></tr>
		<tr><td>Q</td><td ><a href="#TQ">Cvq Types</a></td></tr>
		<tr><td>Z</td><td ><a href="#TZ">Classes</a></td></tr>
		<tr><td>D</td><td ><a href="#TD">Destructors</a></td></tr>
		<tr><td>E</td><td ><a href="#TE">Enumerations</a></td></tr>
		<tr><td>Fd</td><td ><a href="#TFd">Fields</a></td></tr>
		<tr><td>Fu</td><td ><a href="#TF">Functions</a></td></tr>
		<tr><td>FT</td><td ><a href="#TFT">Function Types</a></td></tr>
		<tr><td>M</td><td ><a href="#TM">Methods</a></td></tr>
		<tr><td>MT</td><td ><a href="#TMT">Method Typess</a></td></tr>
		<tr><td>N</td><td ><a href="#TN">Namespaces</a></td></tr>
		<tr><td>OpM</td><td ><a href="#TOM">Operator Methods</a></td></tr>
		<tr><td>OpF</td><td ><a href="#TOF">Operator Functions</a></td></tr>
		<tr><td>O</td><td ><a href="#TO">Offset Types</a></td></tr>
		<tr><td>P</td><td ><a href="#TP">Pointer Types</a></td></tr>
		<tr><td>R</td><td ><a href="#TR">Reference Types</a></td></tr>
		<tr><td>S</td><td ><a href="#TS">Structures</a></td></tr>
		<tr><td>TT</td><td ><a href="#TT">Typedefs</a></td></tr>
		<tr><td>U</td><td ><a href="#TU">Unions</a></td></tr>
		<tr><td>V</td><td ><a href="#TV">Variables</a></td></tr>
	</table><hr/>

	<!-- =============================================== -->
    <table border="1">
		<a name="TB"></a>
		<thead>
			<tr align="center" colspan="5">Builtin Types</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
			</tr>
		</thead>
			<xsl:apply-templates select="FundamentalType">
				<xsl:sort select="@id"/>
			</xsl:apply-templates>
		</table><hr/>

	<!-- =============================================== -->
		<table border="1">
		<a name="TN"></a>
		<thead>
			<tr align="center" colspan="5">Namespaces</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">members</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Namespace">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TZ"></a>
		<thead>
			<tr align="center" colspan="5">Classes</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">bases</td>
				<td align="center">members</td>
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Class">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TS"></a>
		<thead>
			<tr align="center" colspan="5">Structures</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">bases</td>
				<td align="center">members</td>
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Struct">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TU"></a>
		<thead>
			<tr align="center" colspan="5">Unions</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">bases</td>
				<td align="center">members</td>
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Union">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TFd"></a>
		<thead>
			<tr align="center" colspan="5">Fields</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">type</td>
				<td align="center">bits</td>
				<td align="center">access</td>
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Field">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TT"></a>
		<thead>
			<tr align="center" colspan="5">Typedefs</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">type</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Typedef">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TA"></a>
		<thead>
			<tr align="center" colspan="2">Arrays</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">type</td>
				<td align="center">min</td>
				<td align="center">max</td>
			</tr>
		</thead>
			<xsl:apply-templates select="ArrayType">
				<xsl:sort select="@id"/>
			</xsl:apply-templates>
		</table><hr/>


		<!-- =============================================== -->
		<table border="1">
		<a name="TP"></a>
		<thead>
			<tr align="center" colspan="2">Pointers</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">type</td>
			</tr>
		</thead>
			<xsl:apply-templates select="PointerType">
				<xsl:sort select="@id"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TO"></a>
		<thead>
			<tr align="center" colspan="2">Offset Types</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">basetype</td>
				<td align="center">type</td>
			</tr>
		</thead>
			<xsl:apply-templates select="OffsetType">
				<xsl:sort select="@id"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TR"></a>
		<thead>
			<tr align="center" colspan="2">References</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">type</td>
			</tr>
		</thead>
			<xsl:apply-templates select="ReferenceType">
				<xsl:sort select="@id"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TQ"></a>
		<thead>
			<tr align="center" colspan="2">CVQ Types</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">type</td>
			</tr>
		</thead>
			<xsl:apply-templates select="CvQualifiedType">
				<xsl:sort select="@id"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TV"></a>
		<thead>
			<tr align="center" colspan="5">Variables</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">type</td>
				<td align="center">access</td>
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Variable">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TM"></a>
		<thead>
			<tr align="center" colspan="5">Methods</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">returns</td>
				<td align="center">throws</td>
				<td align="center">arguments</td>
				<td align="center">access</td>
				<td align="center">static</td>
                <td align="center">const</td> <!--MINE-->
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Method">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TOM"></a>
		<thead>
			<tr align="center" colspan="5">Operator Methods</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">returns</td>
				<td align="center">throws</td>
				<td align="center">arguments</td>
				<td align="center">access</td>
				<td align="center">static</td>
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="OperatorMethod">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TMT"></a>
		<thead>
			<tr align="center" colspan="5">Method Types</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">basetype</td>
				<td align="center">returns</td>
				<td align="center">arguments</td>
				<td align="center">const</td>
			</tr>
		</thead>
			<xsl:apply-templates select="MethodType">
				<xsl:sort select="@id"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TCT"></a>
		<thead>
			<tr align="center" colspan="5">Converters</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">returns</td>
				<td align="center">throws</td>
				<td align="center">access</td>
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Converter">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TF"></a>
		<thead>
			<tr align="center" colspan="5">Functions</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">returns</td>
				<td align="center">throws</td>
				<td align="center">arguments</td>
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Function">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TOF"></a>
		<thead>
			<tr align="center" colspan="5">Operator Functions</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">returns</td>
				<td align="center">throws</td>
				<td align="center">arguments</td>
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="OperatorFunction">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TFT"></a>
		<thead>
			<tr align="center" colspan="5">Function Types</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">returns</td>
				<td align="center">arguments</td>
			</tr>
		</thead>
			<xsl:apply-templates select="FunctionType">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TC"></a>
		<thead>
			<tr align="center" colspan="5">Constructors</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">throws</td>
				<td align="center">arguments</td>
				<td align="center">access</td>
				<td align="center">artificial</td>
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Constructor">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TD"></a>
		<thead>
			<tr align="center" colspan="5">Destructors</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">throws</td>
				<td align="center">access</td>
				<td align="center">virtual</td>
				<td align="center">artificial</td>
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Destructor">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<a name="TE"></a>
		<thead>
			<tr align="center" colspan="5">Enumerations</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
				<td align="center">context</td>
				<td align="center">artificial</td>
				<td align="center">file</td>
				<td align="center">line</td>
			</tr>
		</thead>
			<xsl:apply-templates select="Enumeration">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>

		<!-- =============================================== -->
		<table border="1">
		<thead>
			<tr align="center" colspan="5">File</tr>
			<tr>
				<td align="center">T</td>
				<td align="center">id</td>
				<td align="center">name</td>
			</tr>
		</thead>
			<xsl:apply-templates select="File">
				<xsl:sort select="@name"/>
			</xsl:apply-templates>
		</table><hr/>
        </html>
    </xsl:template>

	<!-- ====================================================================== -->
    <xsl:template match = "Class">
		<tr>
			<td>Z</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td>
				<xsl:call-template name="tokenize">
					<xsl:with-param name="string" select="@bases" />
				</xsl:call-template>
			</td>
			<td>
				<xsl:call-template name="tokenize">
					<xsl:with-param name="string" select="@members" />
				</xsl:call-template>
			</td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Struct">
		<tr>
			<td>S</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td>
				<xsl:call-template name="tokenize">
						<xsl:with-param name="string" select="@bases" />
				</xsl:call-template>
			</td>
			<td>
				<xsl:call-template name="tokenize">
						<xsl:with-param name="string" select="@members" />
				</xsl:call-template>
			</td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Union">
		<tr>
			<td>U</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td>
				<xsl:call-template name="tokenize">
						<xsl:with-param name="string" select="@bases" />
				</xsl:call-template>
			</td>
			<td>
				<xsl:call-template name="tokenize">
						<xsl:with-param name="string" select="@members" />
				</xsl:call-template>
			</td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Namespace">
		<tr>
			<td>N</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td>
				<xsl:call-template name="tokenize">
						<xsl:with-param name="string" select="@members" />
				</xsl:call-template>
			</td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Field">
		<tr>
			<td>Fd</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td><a href="#{@type}"><xsl:value-of select="@type"/></a></td>
			<td><xsl:value-of select="@access"/></td>
			<td><xsl:value-of select="@bits"/></td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Typedef">
		<tr>
			<td>T</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td><a href="#{@type}"><xsl:value-of select="@type"/></a></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "ArrayType">
		<tr>
			<td>A</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><a href="#{@type}"><xsl:value-of select="@type"/></a></td>
			<td><a name="{@min}"><xsl:value-of select="@min"/></a></td>
			<td><a name="{@max}"><xsl:value-of select="@max"/></a></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "PointerType">
		<tr>
			<td>P</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><a href="#{@type}"><xsl:value-of select="@type"/></a></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "OffsetType">
		<tr>
			<td>O</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><a href="#{@basetype}"><xsl:value-of select="@basetype"/></a></td>
			<td><a href="#{@type}"><xsl:value-of select="@type"/></a></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "ReferenceType">
		<tr>
			<td>R</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><a href="#{@type}"><xsl:value-of select="@type"/></a></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "CvQualifiedType">
		<tr>
			<td>Q</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><a href="#{@type}"><xsl:value-of select="@type"/></a></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "FundamentalType">
		<tr>
			<td>B</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Variable">
		<tr>
			<td>V</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td><a href="#{@type}"><xsl:value-of select="@type"/></a></td>
			<td><xsl:value-of select="@access"/></td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Method">
		<tr>
			<td>M</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td><a href="#{@returns}"><xsl:value-of select="@returns"/></a></td>
			<td>
				<xsl:call-template name="tokenize">
					<xsl:with-param name="string" select="@throw" />
				</xsl:call-template>
			</td>
			<td><xsl:value-of select="@demangled"/></td>
			<td><xsl:value-of select="@access"/></td>
			<td>
				<xsl:choose>
					<xsl:when test="@static='1'">true</xsl:when>
					<xsl:otherwise>false</xsl:otherwise>
				</xsl:choose>
			</td>
            <td>
                <xsl:choose>
                    <xsl:when test="@const='1'">true</xsl:when>
                    <xsl:otherwise>false</xsl:otherwise>
                </xsl:choose>
            </td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "MethodType">
		<tr>
			<td>MT</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><a href="#{@basetype}"><xsl:value-of select="@basetype"/></a></td>
			<td><a href="#{@returns}"><xsl:value-of select="@returns"/></a></td>
			<td><xsl:apply-templates select="Argument"/></td>
			<td>
				<xsl:choose>
					<xsl:when test="@const='1'">true</xsl:when>
					<xsl:otherwise>false</xsl:otherwise>
				</xsl:choose>
			</td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "OperatorMethod">
		<tr>
			<td>OpM</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><a href="#{@basetype}"><xsl:value-of select="@basetype"/></a></td>
			<td><a href="#{@returns}"><xsl:value-of select="@returns"/></a></td>
			<td>
				<xsl:call-template name="tokenize">
					<xsl:with-param name="string" select="@throw" />
				</xsl:call-template>
			</td>
			<td><xsl:apply-templates select="Argument"/></td>
			<td><xsl:value-of select="@access"/></td>
			<td>
				<xsl:choose>
					<xsl:when test="@static='1'">true</xsl:when>
					<xsl:otherwise>false</xsl:otherwise>
				</xsl:choose>
			</td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Converter">
		<tr>
			<td>Cnv</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td><a href="#{@returns}"><xsl:value-of select="@returns"/></a></td>
			<td>
				<xsl:call-template name="tokenize">
					<xsl:with-param name="string" select="@throw" />
				</xsl:call-template>
			</td>
			<td><xsl:value-of select="@access"/></td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Function">
		<tr>
			<td>F</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td><a href="#{@returns}"><xsl:value-of select="@returns"/></a></td>
			<td>
				<xsl:call-template name="tokenize">
					<xsl:with-param name="string" select="@throw" />
				</xsl:call-template>
			</td>
			<td><xsl:apply-templates select="Argument"/></td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "OperatorFunction">
		<tr>
			<td>OpF</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td><a href="#{@returns}"><xsl:value-of select="@returns"/></a></td>
			<td>
				<xsl:call-template name="tokenize">
					<xsl:with-param name="string" select="@throw" />
				</xsl:call-template>
			</td>
			<td><xsl:apply-templates select="Argument"/></td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "FunctionType">
		<tr>
			<td>FT</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><a href="#{@returns}"><xsl:value-of select="@returns"/></a></td>
			<td><xsl:apply-templates select="Argument"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Destructor">
		<tr>
			<td>D</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td>
				<xsl:call-template name="tokenize">
					<xsl:with-param name="string" select="@throw" />
				</xsl:call-template>
			</td>
			<td><xsl:value-of select="@access"/></td>
			<td>
				<xsl:choose>
					<xsl:when test="@virtual='1'">true</xsl:when>
					<xsl:otherwise>false</xsl:otherwise>
				</xsl:choose>
			</td>
			<td>
				<xsl:choose>
					<xsl:when test="@artificial='1'">true</xsl:when>
					<xsl:otherwise>false</xsl:otherwise>
				</xsl:choose>
			</td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Constructor">
		<tr>
			<td>Co</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td>
				<xsl:call-template name="tokenize">
					<xsl:with-param name="string" select="@throw" />
				</xsl:call-template>
			</td>
			<td><xsl:apply-templates select="Argument"/></td>
			<td><xsl:value-of select="@access"/></td>
			<td>
				<xsl:choose>
					<xsl:when test="@artificial='1'">true</xsl:when>
					<xsl:otherwise>false</xsl:otherwise>
				</xsl:choose>
			</td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Enumeration">
		<tr>
			<td>En</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><xsl:value-of select="@name"/></td>
			<td><a href="#{@context}"><xsl:value-of select="@context"/></a></td>
			<td>
				<xsl:choose>
					<xsl:when test="@artificial='1'">true</xsl:when>
					<xsl:otherwise>false</xsl:otherwise>
				</xsl:choose>
			</td>
			<td><a href="#{@file}"><xsl:value-of select="@file"/></a></td>
			<td><xsl:value-of select="@line"/></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "File">
		<tr>
			<td>Fd</td>
			<td><a name="{@id}"><xsl:value-of select="@id"/></a></td>
			<td><a href="{@name}"><xsl:value-of select="@name"/></a></td>
		</tr>
    </xsl:template>

	<!-- =============================================== -->
    <xsl:template match = "Argument">
		<a href="#{@type}"><xsl:value-of select="@type"/></a>
    </xsl:template>

	<!--- ========== Tokenizer ================== -->
	<xsl:template name="tokenize">
	   <xsl:param name="string" select="''" />
	   <xsl:param name="delimiters" select="' &#x9; '" />
	   <xsl:choose>
		  <xsl:when test="not($string)" />
		  <xsl:when test="not($delimiters)">
			 <xsl:call-template name="_tokenize-characters">
				<xsl:with-param name="string" select="$string" />
			 </xsl:call-template>
		  </xsl:when>
		  <xsl:otherwise>
			 <xsl:call-template name="_tokenize-delimiters">
				<xsl:with-param name="string" select="$string" />
				<xsl:with-param name="delimiters"	select="$delimiters" />
			 </xsl:call-template>
		  </xsl:otherwise>
	   </xsl:choose>
	</xsl:template>

	<!-- =============================================== -->
	<xsl:template name="_tokenize-characters">
	   <xsl:param name="string" />
	   <xsl:if test="$string">
		  <a href="#{$string}">
			 <xsl:value-of select="substring($string, 1, 1)" />
		  </a>
		  <xsl:call-template name="_tokenize-characters">
			 <xsl:with-param name="string"	 select="substring($string, 2)" />
		  </xsl:call-template>
	   </xsl:if>
	</xsl:template>

	<!-- =============================================== -->
	<xsl:template name="_tokenize-delimiters">
	   <xsl:param name="string" />
	   <xsl:param name="delimiters" />
	   <xsl:variable name="delimiter"	 select="substring($delimiters, 1, 1)" />
	   <xsl:choose>
		  <xsl:when test="not($delimiter)">
			 <a href="#{$string}">
				<xsl:value-of select="$string" />
			 </a>
		  </xsl:when>
		  <xsl:when test="contains($string, $delimiter)">
			 <xsl:if test="not(starts-with($string, $delimiter))">
				<xsl:call-template name="_tokenize-delimiters">
				   <xsl:with-param name="string"  select="substring-before($string, $delimiter)" />
				   <xsl:with-param name="delimiters"  select="substring($delimiters, 2)" />
				</xsl:call-template>
			 </xsl:if>
			 <xsl:call-template name="_tokenize-delimiters">
				<xsl:with-param name="string"	select="substring-after($string, $delimiter)" />
				<xsl:with-param name="delimiters"	select="$delimiters" />
			 </xsl:call-template>
		  </xsl:when>

		  <xsl:when test="starts-with($string, 'private:')">
		  	<xsl:call-template name="_tokenize-delimiters">
				<xsl:with-param name="string"	select="substring($string, 9)" />
			 </xsl:call-template>
		  </xsl:when>

		  <xsl:when test="starts-with($string, 'protected:')">
		  	<xsl:call-template name="_tokenize-delimiters">
				<xsl:with-param name="string"	select="substring($string, 11)" />
			 </xsl:call-template>
		  </xsl:when>

		  <xsl:otherwise>
			 <xsl:call-template name="_tokenize-delimiters">
				<xsl:with-param name="string"	select="$string" />
				<xsl:with-param name="delimiters"	select="substring($delimiters, 2)" />
			 </xsl:call-template>
		  </xsl:otherwise>
	   </xsl:choose>
	</xsl:template>

</xsl:stylesheet>
