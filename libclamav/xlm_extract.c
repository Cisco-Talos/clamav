/*
 *  Extract XLM (Excel 4.0) macro source code for component MS Office Documents
 *
 *  Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Jonas Zaddach
 *
 *  This code is partly based on and inspired by plugin_biff from ole_dump (Didier Stevens)
 *  https://github.com/DidierStevens/DidierStevensSuite/blob/master/plugin_biff.py
 *  plugin_biff.py is public domain without copyright.
 *
 *  See https://www.loc.gov/preservation/digital/formats/digformatspecs/Excel97-2007BinaryFileFormat(xls)Specification.pdf .
 *  See https://www.openoffice.org/sc/excelfileformat.pdf
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#include <fcntl.h>
#include <stdbool.h>

#include "fmap.h"
#include "entconv.h"
#include "xlm_extract.h"
#include "scanners.h"

#define min(x, y) (((x) < (y)) ? (x) : (y))

// clang-format off
const char *OPCODE_NAMES[] = {
        NULL,                                                         //0
        NULL,                                                         //1
        NULL,                                                         //2
        NULL,                                                         //3
        NULL,                                                         //4
        NULL,                                                         //5
        "FORMULA : Cell Formula",                                     //6
        NULL,                                                         //7
        NULL,                                                         //8
        NULL,                                                         //9
        "EOF : End of File",                                          //10
        NULL,                                                         //11
        "CALCCOUNT : Iteration Count",                                //12
        "CALCMODE : Calculation Mode",                                //13
        "PRECISION : Precision",                                      //14
        "REFMODE : Reference Mode",                                   //15
        "DELTA : Iteration Increment",                                //16
        "ITERATION : Iteration Mode",                                 //17
        "PROTECT : Protection Flag",                                  //18
        "PASSWORD : Protection Password",                             //19
        "HEADER : Print Header on Each Page",                         //20
        "FOOTER : Print Footer on Each Page",                         //21
        "EXTERNCOUNT : Number of External References",                //22
        "EXTERNSHEET : External Reference",                           //23
        "LABEL : Cell Value, String Constant",                        //24
        "WINDOWPROTECT : Windows Are Protected",                      //25
        "VERTICALPAGEBREAKS : Explicit Column Page Breaks",           //26
        "HORIZONTALPAGEBREAKS : Explicit Row Page Breaks",            //27
        "NOTE : Comment Associated with a Cell",                      //28
        "SELECTION : Current Selection",                              //29
        NULL,                                                         //30
        NULL,                                                         //31
        NULL,                                                         //32
        NULL,                                                         //33
        "1904 : 1904 Date System",                                    //34
        NULL,                                                         //35
        NULL,                                                         //36
        NULL,                                                         //37
        "LEFTMARGIN : Left Margin Measurement",                       //38
        "RIGHTMARGIN : Right Margin Measurement",                     //39
        "TOPMARGIN : Top Margin Measurement",                         //40
        "BOTTOMMARGIN : Bottom Margin Measurement",                   //41
        "PRINTHEADERS : Print Row/Column Labels",                     //42
        "PRINTGRIDLINES : Print Gridlines Flag",                      //43
        NULL,                                                         //44
        NULL,                                                         //45
        NULL,                                                         //46
        "FILEPASS : File Is Password-Protected",                      //47
        NULL,                                                         //48
        NULL,                                                         //49
        NULL,                                                         //50
        NULL,                                                         //51
        NULL,                                                         //52
        NULL,                                                         //53
        NULL,                                                         //54
        NULL,                                                         //55
        NULL,                                                         //56
        NULL,                                                         //57
        NULL,                                                         //58
        NULL,                                                         //59
        "CONTINUE : Continues Long Records",                          //60
        "WINDOW1 : Window Information",                               //61
        NULL,                                                         //62
        NULL,                                                         //63
        "BACKUP : Save Backup Version of the File",                   //64
        "PANE : Number of Panes and Their Position",                  //65
        "CODEPAGE : Default Code Page",                               //66
        NULL,                                                         //67
        NULL,                                                         //68
        NULL,                                                         //69
        NULL,                                                         //70
        NULL,                                                         //71
        NULL,                                                         //72
        NULL,                                                         //73
        NULL,                                                         //74
        NULL,                                                         //75
        NULL,                                                         //76
        "PLS : Environment-Specific Print Record",                    //77
        NULL,                                                         //78
        NULL,                                                         //79
        "DCON : Data Consolidation Information",                      //80
        "DCONREF : Data Consolidation References",                    //81
        "DCONNAME : Data Consolidation Named References",             //82
        NULL,                                                         //83
        NULL,                                                         //84
        "DEFCOLWIDTH : Default Width for Columns",                    //85
        NULL,                                                         //86
        NULL,                                                         //87
        NULL,                                                         //88
        "XCT : CRN Record Count",                                     //89
        "CRN : Nonresident Operands",                                 //90
        "FILESHARING : File-Sharing Information",                     //91
        "WRITEACCESS : Write Access User Name",                       //92
        "OBJ : Describes a Graphic Object",                           //93
        "UNCALCED : Recalculation Status",                            //94
        "SAVERECALC : Recalculate Before Save",                       //95
        "TEMPLATE : Workbook Is a Template",                          //96
        NULL,                                                         //97
        NULL,                                                         //98
        "OBJPROTECT : Objects Are Protected",                         //99
        NULL,                                                         //100
        NULL,                                                         //101
        NULL,                                                         //102
        NULL,                                                         //103
        NULL,                                                         //104
        NULL,                                                         //105
        NULL,                                                         //106
        NULL,                                                         //107
        NULL,                                                         //108
        NULL,                                                         //109
        NULL,                                                         //110
        NULL,                                                         //111
        NULL,                                                         //112
        NULL,                                                         //113
        NULL,                                                         //114
        NULL,                                                         //115
        NULL,                                                         //116
        NULL,                                                         //117
        NULL,                                                         //118
        NULL,                                                         //119
        NULL,                                                         //120
        NULL,                                                         //121
        NULL,                                                         //122
        NULL,                                                         //123
        NULL,                                                         //124
        "COLINFO : Column Formatting Information",                    //125
        "RK : Cell Value, RK Number",                                 //126
        "IMDATA : Image Data",                                        //127
        "GUTS : Size of Row and Column Gutters",                      //128
        "WSBOOL : Additional Workspace Information",                  //129
        "GRIDSET : State Change of Gridlines Option",                 //130
        "HCENTER : Center Between Horizontal Margins",                //131
        "VCENTER : Center Between Vertical Margins",                  //132
        "BOUNDSHEET : Sheet Information",                             //133
        "WRITEPROT : Workbook Is Write-Protected",                    //134
        "ADDIN : Workbook Is an Add-in Macro",                        //135
        "EDG : Edition Globals",                                      //136
        "PUB : Publisher",                                            //137
        NULL,                                                         //138
        NULL,                                                         //139
        "COUNTRY : Default Country and WIN.INI Country",              //140
        "HIDEOBJ : Object Display Options",                           //141
        NULL,                                                         //142
        NULL,                                                         //143
        "SORT : Sorting Options",                                     //144
        "SUB : Subscriber",                                           //145
        "PALETTE : Color Palette Definition",                         //146
        NULL,                                                         //147
        "LHRECORD : .WK? File Conversion Information",                //148
        "LHNGRAPH : Named Graph Information",                         //149
        "SOUND : Sound Note",                                         //150
        NULL,                                                         //151
        "LPR : Sheet Was Printed Using LINE.PRINT(",                  //152
        "STANDARDWIDTH : Standard Column Width",                      //153
        "FNGROUPNAME : Function Group Name",                          //154
        "FILTERMODE : Sheet Contains Filtered List",                  //155
        "FNGROUPCOUNT : Built-in Function Group Count",               //156
        "AUTOFILTERINFO : Drop-Down Arrow Count",                     //157
        "AUTOFILTER : AutoFilter Data",                               //158
        NULL,                                                         //159
        "SCL : Window Zoom Magnification",                            //160
        "SETUP : Page Setup",                                         //161
        NULL,                                                         //162
        NULL,                                                         //163
        NULL,                                                         //164
        NULL,                                                         //165
        NULL,                                                         //166
        NULL,                                                         //167
        NULL,                                                         //168
        "COORDLIST : Polygon Object Vertex Coordinates",              //169
        NULL,                                                         //170
        "GCW : Global Column-Width Flags",                            //171
        NULL,                                                         //172
        NULL,                                                         //173
        "SCENMAN : Scenario Output Data",                             //174
        "SCENARIO : Scenario Data",                                   //175
        "SXVIEW : View Definition",                                   //176
        "SXVD : View Fields",                                         //177
        "SXVI : View Item",                                           //178
        NULL,                                                         //179
        "SXIVD : Row/Column Field IDs",                               //180
        "SXLI : Line Item Array",                                     //181
        "SXPI : Page Item",                                           //182
        NULL,                                                         //183
        "DOCROUTE : Routing Slip Information",                        //184
        "RECIPNAME : Recipient Name",                                 //185
        NULL,                                                         //186
        NULL,                                                         //187
        "SHRFMLA : Shared Formula",                                   //188
        "MULRK : Multiple  RK Cells",                                 //189
        "MULBLANK : Multiple Blank Cells",                            //190
        NULL,                                                         //191
        NULL,                                                         //192
        "MMS :  ADDMENU / DELMENU Record Group Count",                //193
        "ADDMENU : Menu Addition",                                    //194
        "DELMENU : Menu Deletion",                                    //195
        NULL,                                                         //196
        "SXDI : Data Item",                                           //197
        "SXDB : PivotTable Cache Data",                               //198
        NULL,                                                         //199
        NULL,                                                         //200
        NULL,                                                         //201
        NULL,                                                         //202
        NULL,                                                         //203
        NULL,                                                         //204
        "SXSTRING : String",                                          //205
        NULL,                                                         //206
        NULL,                                                         //207
        "SXTBL : Multiple Consolidation Source Info",                 //208
        "SXTBRGIITM : Page Item Name Count",                          //209
        "SXTBPG : Page Item Indexes",                                 //210
        "OBPROJ : Visual Basic Project",                              //211
        NULL,                                                         //212
        "SXIDSTM : Stream ID",                                        //213
        "RSTRING : Cell with Character Formatting",                   //214
        "DBCELL : Stream Offsets",                                    //215
        NULL,                                                         //216
        NULL,                                                         //217
        "BOOKBOOL : Workbook Option Flag",                            //218
        NULL,                                                         //219
        "SXEXT : External Source Information",                        //220
        "SCENPROTECT : Scenario Protection",                          //221
        "OLESIZE : Size of OLE Object",                               //222
        "UDDESC : Description String for Chart Autoformat",           //223
        "XF : Extended Format",                                       //224
        "INTERFACEHDR : Beginning of User Interface Records",         //225
        "INTERFACEEND : End of User Interface Records",               //226
        "SXVS : View Source",                                         //227
        NULL,                                                         //228
        "MERGECELLS : Merged Cells",                                  //229
        NULL,                                                         //230
        NULL,                                                         //231
        NULL,                                                         //232
        NULL,                                                         //233
        "TABIDCONF : Sheet Tab ID of Conflict History",               //234
        "MSODRAWINGGROUP : Microsoft Office Drawing Group",           //235
        "MSODRAWING : Microsoft Office Drawing",                      //236
        "MSODRAWINGSELECTION : Microsoft Office Drawing Selection",   //237
        NULL,                                                         //238
        NULL,                                                         //239
        "SXRULE : PivotTable Rule Data",                              //240
        "SXEX : PivotTable View Extended Information",                //241
        "SXFILT : PivotTable Rule Filter",                            //242
        NULL,                                                         //243
        "SXDXF : Pivot Table Formatting",                             //244
        "SXITM : Pivot Table Item Indexes",                           //245
        "SXNAME : PivotTable Name",                                   //246
        "SXSELECT : PivotTable Selection Information",                //247
        "SXPAIR : PivotTable Name Pair",                              //248
        "SXFMLA : Pivot Table Parsed Expression",                     //249
        NULL,                                                         //250
        "SXFORMAT : PivotTable Format Record",                        //251
        "SST : Shared String Table",                                  //252
        "LABELSST : Cell Value, String Constant/ SST",                //253
        NULL,                                                         //254
        "EXTSST : Extended Shared String Table",                      //255
        "SXVDEX : Extended PivotTable View Fields",                   //256
        NULL,                                                         //257
        NULL,                                                         //258
        "SXFORMULA : PivotTable Formula Record",                      //259
        NULL,                                                         //260
        NULL,                                                         //261
        NULL,                                                         //262
        NULL,                                                         //263
        NULL,                                                         //264
        NULL,                                                         //265
        NULL,                                                         //266
        NULL,                                                         //267
        NULL,                                                         //268
        NULL,                                                         //269
        NULL,                                                         //270
        NULL,                                                         //271
        NULL,                                                         //272
        NULL,                                                         //273
        NULL,                                                         //274
        NULL,                                                         //275
        NULL,                                                         //276
        NULL,                                                         //277
        NULL,                                                         //278
        NULL,                                                         //279
        NULL,                                                         //280
        NULL,                                                         //281
        NULL,                                                         //282
        NULL,                                                         //283
        NULL,                                                         //284
        NULL,                                                         //285
        NULL,                                                         //286
        NULL,                                                         //287
        NULL,                                                         //288
        NULL,                                                         //289
        "SXDBEX : PivotTable Cache Data",                             //290
        NULL,                                                         //291
        NULL,                                                         //292
        NULL,                                                         //293
        NULL,                                                         //294
        NULL,                                                         //295
        NULL,                                                         //296
        NULL,                                                         //297
        NULL,                                                         //298
        NULL,                                                         //299
        NULL,                                                         //300
        NULL,                                                         //301
        NULL,                                                         //302
        NULL,                                                         //303
        NULL,                                                         //304
        NULL,                                                         //305
        NULL,                                                         //306
        NULL,                                                         //307
        NULL,                                                         //308
        NULL,                                                         //309
        NULL,                                                         //310
        NULL,                                                         //311
        NULL,                                                         //312
        NULL,                                                         //313
        NULL,                                                         //314
        NULL,                                                         //315
        NULL,                                                         //316
        "TABID : Sheet Tab Index Array",                              //317
        NULL,                                                         //318
        NULL,                                                         //319
        NULL,                                                         //320
        NULL,                                                         //321
        NULL,                                                         //322
        NULL,                                                         //323
        NULL,                                                         //324
        NULL,                                                         //325
        NULL,                                                         //326
        NULL,                                                         //327
        NULL,                                                         //328
        NULL,                                                         //329
        NULL,                                                         //330
        NULL,                                                         //331
        NULL,                                                         //332
        NULL,                                                         //333
        NULL,                                                         //334
        NULL,                                                         //335
        NULL,                                                         //336
        NULL,                                                         //337
        NULL,                                                         //338
        NULL,                                                         //339
        NULL,                                                         //340
        NULL,                                                         //341
        NULL,                                                         //342
        NULL,                                                         //343
        NULL,                                                         //344
        NULL,                                                         //345
        NULL,                                                         //346
        NULL,                                                         //347
        NULL,                                                         //348
        NULL,                                                         //349
        NULL,                                                         //350
        NULL,                                                         //351
        "USESELFS : Natural Language Formulas Flag",                  //352
        "DSF : Double Stream File",                                   //353
        "XL5MODIFY : Flag for  DSF",                                  //354
        NULL,                                                         //355
        NULL,                                                         //356
        NULL,                                                         //357
        NULL,                                                         //358
        NULL,                                                         //359
        NULL,                                                         //360
        NULL,                                                         //361
        NULL,                                                         //362
        NULL,                                                         //363
        NULL,                                                         //364
        NULL,                                                         //365
        NULL,                                                         //366
        NULL,                                                         //367
        NULL,                                                         //368
        NULL,                                                         //369
        NULL,                                                         //370
        NULL,                                                         //371
        NULL,                                                         //372
        NULL,                                                         //373
        NULL,                                                         //374
        NULL,                                                         //375
        NULL,                                                         //376
        NULL,                                                         //377
        NULL,                                                         //378
        NULL,                                                         //379
        NULL,                                                         //380
        NULL,                                                         //381
        NULL,                                                         //382
        NULL,                                                         //383
        NULL,                                                         //384
        NULL,                                                         //385
        NULL,                                                         //386
        NULL,                                                         //387
        NULL,                                                         //388
        NULL,                                                         //389
        NULL,                                                         //390
        NULL,                                                         //391
        NULL,                                                         //392
        NULL,                                                         //393
        NULL,                                                         //394
        NULL,                                                         //395
        NULL,                                                         //396
        NULL,                                                         //397
        NULL,                                                         //398
        NULL,                                                         //399
        NULL,                                                         //400
        NULL,                                                         //401
        NULL,                                                         //402
        NULL,                                                         //403
        NULL,                                                         //404
        NULL,                                                         //405
        NULL,                                                         //406
        NULL,                                                         //407
        NULL,                                                         //408
        NULL,                                                         //409
        NULL,                                                         //410
        NULL,                                                         //411
        NULL,                                                         //412
        NULL,                                                         //413
        NULL,                                                         //414
        NULL,                                                         //415
        NULL,                                                         //416
        NULL,                                                         //417
        NULL,                                                         //418
        NULL,                                                         //419
        NULL,                                                         //420
        "FILESHARING2 : File-Sharing Information for Shared Lists",   //421
        NULL,                                                         //422
        NULL,                                                         //423
        NULL,                                                         //424
        "USERBVIEW : Workbook Custom View Settings",                  //425
        "USERSVIEWBEGIN : Custom View Settings",                      //426
        "USERSVIEWEND : End of Custom View Records",                  //427
        NULL,                                                         //428
        "QSI : External Data Range",                                  //429
        "SUPBOOK : Supporting Workbook",                              //430
        "PROT4REV : Shared Workbook Protection Flag",                 //431
        "CONDFMT : Conditional Formatting Range Information",         //432
        "CF : Conditional Formatting Conditions",                     //433
        "DVAL : Data Validation Information",                         //434
        NULL,                                                         //435
        NULL,                                                         //436
        "DCONBIN : Data Consolidation Information",                   //437
        "TXO : Text Object",                                          //438
        "REFRESHALL : Refresh Flag",                                  //439
        "HLINK : Hyperlink",                                          //440
        NULL,                                                         //441
        NULL,                                                         //442
        "SXFDBTYPE : SQL Datatype Identifier",                        //443
        "PROT4REVPASS : Shared Workbook Protection Password",         //444
        NULL,                                                         //445
        "DV : Data Validation Criteria",                              //446
        NULL,                                                         //447
        "EXCEL9FILE : Excel 9 File",                                  //448
        "RECALCID : Recalc Information",                              //449
        NULL,                                                         //450
        NULL,                                                         //451
        NULL,                                                         //452
        NULL,                                                         //453
        NULL,                                                         //454
        NULL,                                                         //455
        NULL,                                                         //456
        NULL,                                                         //457
        NULL,                                                         //458
        NULL,                                                         //459
        NULL,                                                         //460
        NULL,                                                         //461
        NULL,                                                         //462
        NULL,                                                         //463
        NULL,                                                         //464
        NULL,                                                         //465
        NULL,                                                         //466
        NULL,                                                         //467
        NULL,                                                         //468
        NULL,                                                         //469
        NULL,                                                         //470
        NULL,                                                         //471
        NULL,                                                         //472
        NULL,                                                         //473
        NULL,                                                         //474
        NULL,                                                         //475
        NULL,                                                         //476
        NULL,                                                         //477
        NULL,                                                         //478
        NULL,                                                         //479
        NULL,                                                         //480
        NULL,                                                         //481
        NULL,                                                         //482
        NULL,                                                         //483
        NULL,                                                         //484
        NULL,                                                         //485
        NULL,                                                         //486
        NULL,                                                         //487
        NULL,                                                         //488
        NULL,                                                         //489
        NULL,                                                         //490
        NULL,                                                         //491
        NULL,                                                         //492
        NULL,                                                         //493
        NULL,                                                         //494
        NULL,                                                         //495
        NULL,                                                         //496
        NULL,                                                         //497
        NULL,                                                         //498
        NULL,                                                         //499
        NULL,                                                         //500
        NULL,                                                         //501
        NULL,                                                         //502
        NULL,                                                         //503
        NULL,                                                         //504
        NULL,                                                         //505
        NULL,                                                         //506
        NULL,                                                         //507
        NULL,                                                         //508
        NULL,                                                         //509
        NULL,                                                         //510
        NULL,                                                         //511
        "DIMENSIONS : Cell Table Size",                               //512
        "BLANK : Cell Value, Blank Cell",                             //513
        NULL,                                                         //514
        "NUMBER : Cell Value, Floating-Point Number",                 //515
        "LABEL : Cell Value, String Constant",                        //516
        "BOOLERR : Cell Value, Boolean or Error",                     //517
        NULL,                                                         //518
        "STRING : String Value of a Formula",                         //519
        "ROW : Describes a Row",                                      //520
        NULL,                                                         //521
        NULL,                                                         //522
        "INDEX : Index Record",                                       //523
        NULL,                                                         //524
        NULL,                                                         //525
        NULL,                                                         //526
        NULL,                                                         //527
        NULL,                                                         //528
        NULL,                                                         //529
        NULL,                                                         //530
        NULL,                                                         //531
        NULL,                                                         //532
        NULL,                                                         //533
        NULL,                                                         //534
        NULL,                                                         //535
        "NAME : Defined Name",                                        //536
        NULL,                                                         //537
        NULL,                                                         //538
        NULL,                                                         //539
        NULL,                                                         //540
        NULL,                                                         //541
        NULL,                                                         //542
        NULL,                                                         //543
        NULL,                                                         //544
        "ARRAY : Array-Entered Formula",                              //545
        NULL,                                                         //546
        "EXTERNNAME : Externally Referenced Name",                    //547
        NULL,                                                         //548
        "DEFAULTROWHEIGHT : Default Row Height",                      //549
        NULL,                                                         //550
        NULL,                                                         //551
        NULL,                                                         //552
        NULL,                                                         //553
        NULL,                                                         //554
        NULL,                                                         //555
        NULL,                                                         //556
        NULL,                                                         //557
        NULL,                                                         //558
        NULL,                                                         //559
        NULL,                                                         //560
        "FONT : Font Description",                                    //561
        NULL,                                                         //562
        NULL,                                                         //563
        NULL,                                                         //564
        NULL,                                                         //565
        "TABLE : Data Table",                                         //566
        NULL,                                                         //567
        NULL,                                                         //568
        NULL,                                                         //569
        NULL,                                                         //570
        NULL,                                                         //571
        NULL,                                                         //572
        NULL,                                                         //573
        "WINDOW2 : Sheet Window Information",                         //574
        NULL,                                                         //575
        NULL,                                                         //576
        NULL,                                                         //577
        NULL,                                                         //578
        NULL,                                                         //579
        NULL,                                                         //580
        NULL,                                                         //581
        NULL,                                                         //582
        NULL,                                                         //583
        NULL,                                                         //584
        NULL,                                                         //585
        NULL,                                                         //586
        NULL,                                                         //587
        NULL,                                                         //588
        NULL,                                                         //589
        NULL,                                                         //590
        NULL,                                                         //591
        NULL,                                                         //592
        NULL,                                                         //593
        NULL,                                                         //594
        NULL,                                                         //595
        NULL,                                                         //596
        NULL,                                                         //597
        NULL,                                                         //598
        NULL,                                                         //599
        NULL,                                                         //600
        NULL,                                                         //601
        NULL,                                                         //602
        NULL,                                                         //603
        NULL,                                                         //604
        NULL,                                                         //605
        NULL,                                                         //606
        NULL,                                                         //607
        NULL,                                                         //608
        NULL,                                                         //609
        NULL,                                                         //610
        NULL,                                                         //611
        NULL,                                                         //612
        NULL,                                                         //613
        NULL,                                                         //614
        NULL,                                                         //615
        NULL,                                                         //616
        NULL,                                                         //617
        NULL,                                                         //618
        NULL,                                                         //619
        NULL,                                                         //620
        NULL,                                                         //621
        NULL,                                                         //622
        NULL,                                                         //623
        NULL,                                                         //624
        NULL,                                                         //625
        NULL,                                                         //626
        NULL,                                                         //627
        NULL,                                                         //628
        NULL,                                                         //629
        NULL,                                                         //630
        NULL,                                                         //631
        NULL,                                                         //632
        NULL,                                                         //633
        NULL,                                                         //634
        NULL,                                                         //635
        NULL,                                                         //636
        NULL,                                                         //637
        NULL,                                                         //638
        NULL,                                                         //639
        NULL,                                                         //640
        NULL,                                                         //641
        NULL,                                                         //642
        NULL,                                                         //643
        NULL,                                                         //644
        NULL,                                                         //645
        NULL,                                                         //646
        NULL,                                                         //647
        NULL,                                                         //648
        NULL,                                                         //649
        NULL,                                                         //650
        NULL,                                                         //651
        NULL,                                                         //652
        NULL,                                                         //653
        NULL,                                                         //654
        NULL,                                                         //655
        NULL,                                                         //656
        NULL,                                                         //657
        NULL,                                                         //658
        "STYLE : Style Information",                                  //659
        NULL,                                                         //660
        NULL,                                                         //661
        NULL,                                                         //662
        NULL,                                                         //663
        NULL,                                                         //664
        NULL,                                                         //665
        NULL,                                                         //666
        NULL,                                                         //667
        NULL,                                                         //668
        NULL,                                                         //669
        NULL,                                                         //670
        NULL,                                                         //671
        NULL,                                                         //672
        NULL,                                                         //673
        NULL,                                                         //674
        NULL,                                                         //675
        NULL,                                                         //676
        NULL,                                                         //677
        NULL,                                                         //678
        NULL,                                                         //679
        NULL,                                                         //680
        NULL,                                                         //681
        NULL,                                                         //682
        NULL,                                                         //683
        NULL,                                                         //684
        NULL,                                                         //685
        NULL,                                                         //686
        NULL,                                                         //687
        NULL,                                                         //688
        NULL,                                                         //689
        NULL,                                                         //690
        NULL,                                                         //691
        NULL,                                                         //692
        NULL,                                                         //693
        NULL,                                                         //694
        NULL,                                                         //695
        NULL,                                                         //696
        NULL,                                                         //697
        NULL,                                                         //698
        NULL,                                                         //699
        NULL,                                                         //700
        NULL,                                                         //701
        NULL,                                                         //702
        NULL,                                                         //703
        NULL,                                                         //704
        NULL,                                                         //705
        NULL,                                                         //706
        NULL,                                                         //707
        NULL,                                                         //708
        NULL,                                                         //709
        NULL,                                                         //710
        NULL,                                                         //711
        NULL,                                                         //712
        NULL,                                                         //713
        NULL,                                                         //714
        NULL,                                                         //715
        NULL,                                                         //716
        NULL,                                                         //717
        NULL,                                                         //718
        NULL,                                                         //719
        NULL,                                                         //720
        NULL,                                                         //721
        NULL,                                                         //722
        NULL,                                                         //723
        NULL,                                                         //724
        NULL,                                                         //725
        NULL,                                                         //726
        NULL,                                                         //727
        NULL,                                                         //728
        NULL,                                                         //729
        NULL,                                                         //730
        NULL,                                                         //731
        NULL,                                                         //732
        NULL,                                                         //733
        NULL,                                                         //734
        NULL,                                                         //735
        NULL,                                                         //736
        NULL,                                                         //737
        NULL,                                                         //738
        NULL,                                                         //739
        NULL,                                                         //740
        NULL,                                                         //741
        NULL,                                                         //742
        NULL,                                                         //743
        NULL,                                                         //744
        NULL,                                                         //745
        NULL,                                                         //746
        NULL,                                                         //747
        NULL,                                                         //748
        NULL,                                                         //749
        NULL,                                                         //750
        NULL,                                                         //751
        NULL,                                                         //752
        NULL,                                                         //753
        NULL,                                                         //754
        NULL,                                                         //755
        NULL,                                                         //756
        NULL,                                                         //757
        NULL,                                                         //758
        NULL,                                                         //759
        NULL,                                                         //760
        NULL,                                                         //761
        NULL,                                                         //762
        NULL,                                                         //763
        NULL,                                                         //764
        NULL,                                                         //765
        NULL,                                                         //766
        NULL,                                                         //767
        NULL,                                                         //768
        NULL,                                                         //769
        NULL,                                                         //770
        NULL,                                                         //771
        NULL,                                                         //772
        NULL,                                                         //773
        NULL,                                                         //774
        NULL,                                                         //775
        NULL,                                                         //776
        NULL,                                                         //777
        NULL,                                                         //778
        NULL,                                                         //779
        NULL,                                                         //780
        NULL,                                                         //781
        NULL,                                                         //782
        NULL,                                                         //783
        NULL,                                                         //784
        NULL,                                                         //785
        NULL,                                                         //786
        NULL,                                                         //787
        NULL,                                                         //788
        NULL,                                                         //789
        NULL,                                                         //790
        NULL,                                                         //791
        NULL,                                                         //792
        NULL,                                                         //793
        NULL,                                                         //794
        NULL,                                                         //795
        NULL,                                                         //796
        NULL,                                                         //797
        NULL,                                                         //798
        NULL,                                                         //799
        NULL,                                                         //800
        NULL,                                                         //801
        NULL,                                                         //802
        NULL,                                                         //803
        NULL,                                                         //804
        NULL,                                                         //805
        NULL,                                                         //806
        NULL,                                                         //807
        NULL,                                                         //808
        NULL,                                                         //809
        NULL,                                                         //810
        NULL,                                                         //811
        NULL,                                                         //812
        NULL,                                                         //813
        NULL,                                                         //814
        NULL,                                                         //815
        NULL,                                                         //816
        NULL,                                                         //817
        NULL,                                                         //818
        NULL,                                                         //819
        NULL,                                                         //820
        NULL,                                                         //821
        NULL,                                                         //822
        NULL,                                                         //823
        NULL,                                                         //824
        NULL,                                                         //825
        NULL,                                                         //826
        NULL,                                                         //827
        NULL,                                                         //828
        NULL,                                                         //829
        NULL,                                                         //830
        NULL,                                                         //831
        NULL,                                                         //832
        NULL,                                                         //833
        NULL,                                                         //834
        NULL,                                                         //835
        NULL,                                                         //836
        NULL,                                                         //837
        NULL,                                                         //838
        NULL,                                                         //839
        NULL,                                                         //840
        NULL,                                                         //841
        NULL,                                                         //842
        NULL,                                                         //843
        NULL,                                                         //844
        NULL,                                                         //845
        NULL,                                                         //846
        NULL,                                                         //847
        NULL,                                                         //848
        NULL,                                                         //849
        NULL,                                                         //850
        NULL,                                                         //851
        NULL,                                                         //852
        NULL,                                                         //853
        NULL,                                                         //854
        NULL,                                                         //855
        NULL,                                                         //856
        NULL,                                                         //857
        NULL,                                                         //858
        NULL,                                                         //859
        NULL,                                                         //860
        NULL,                                                         //861
        NULL,                                                         //862
        NULL,                                                         //863
        NULL,                                                         //864
        NULL,                                                         //865
        NULL,                                                         //866
        NULL,                                                         //867
        NULL,                                                         //868
        NULL,                                                         //869
        NULL,                                                         //870
        NULL,                                                         //871
        NULL,                                                         //872
        NULL,                                                         //873
        NULL,                                                         //874
        NULL,                                                         //875
        NULL,                                                         //876
        NULL,                                                         //877
        NULL,                                                         //878
        NULL,                                                         //879
        NULL,                                                         //880
        NULL,                                                         //881
        NULL,                                                         //882
        NULL,                                                         //883
        NULL,                                                         //884
        NULL,                                                         //885
        NULL,                                                         //886
        NULL,                                                         //887
        NULL,                                                         //888
        NULL,                                                         //889
        NULL,                                                         //890
        NULL,                                                         //891
        NULL,                                                         //892
        NULL,                                                         //893
        NULL,                                                         //894
        NULL,                                                         //895
        NULL,                                                         //896
        NULL,                                                         //897
        NULL,                                                         //898
        NULL,                                                         //899
        NULL,                                                         //900
        NULL,                                                         //901
        NULL,                                                         //902
        NULL,                                                         //903
        NULL,                                                         //904
        NULL,                                                         //905
        NULL,                                                         //906
        NULL,                                                         //907
        NULL,                                                         //908
        NULL,                                                         //909
        NULL,                                                         //910
        NULL,                                                         //911
        NULL,                                                         //912
        NULL,                                                         //913
        NULL,                                                         //914
        NULL,                                                         //915
        NULL,                                                         //916
        NULL,                                                         //917
        NULL,                                                         //918
        NULL,                                                         //919
        NULL,                                                         //920
        NULL,                                                         //921
        NULL,                                                         //922
        NULL,                                                         //923
        NULL,                                                         //924
        NULL,                                                         //925
        NULL,                                                         //926
        NULL,                                                         //927
        NULL,                                                         //928
        NULL,                                                         //929
        NULL,                                                         //930
        NULL,                                                         //931
        NULL,                                                         //932
        NULL,                                                         //933
        NULL,                                                         //934
        NULL,                                                         //935
        NULL,                                                         //936
        NULL,                                                         //937
        NULL,                                                         //938
        NULL,                                                         //939
        NULL,                                                         //940
        NULL,                                                         //941
        NULL,                                                         //942
        NULL,                                                         //943
        NULL,                                                         //944
        NULL,                                                         //945
        NULL,                                                         //946
        NULL,                                                         //947
        NULL,                                                         //948
        NULL,                                                         //949
        NULL,                                                         //950
        NULL,                                                         //951
        NULL,                                                         //952
        NULL,                                                         //953
        NULL,                                                         //954
        NULL,                                                         //955
        NULL,                                                         //956
        NULL,                                                         //957
        NULL,                                                         //958
        NULL,                                                         //959
        NULL,                                                         //960
        NULL,                                                         //961
        NULL,                                                         //962
        NULL,                                                         //963
        NULL,                                                         //964
        NULL,                                                         //965
        NULL,                                                         //966
        NULL,                                                         //967
        NULL,                                                         //968
        NULL,                                                         //969
        NULL,                                                         //970
        NULL,                                                         //971
        NULL,                                                         //972
        NULL,                                                         //973
        NULL,                                                         //974
        NULL,                                                         //975
        NULL,                                                         //976
        NULL,                                                         //977
        NULL,                                                         //978
        NULL,                                                         //979
        NULL,                                                         //980
        NULL,                                                         //981
        NULL,                                                         //982
        NULL,                                                         //983
        NULL,                                                         //984
        NULL,                                                         //985
        NULL,                                                         //986
        NULL,                                                         //987
        NULL,                                                         //988
        NULL,                                                         //989
        NULL,                                                         //990
        NULL,                                                         //991
        NULL,                                                         //992
        NULL,                                                         //993
        NULL,                                                         //994
        NULL,                                                         //995
        NULL,                                                         //996
        NULL,                                                         //997
        NULL,                                                         //998
        NULL,                                                         //999
        NULL,                                                         //1000
        NULL,                                                         //1001
        NULL,                                                         //1002
        NULL,                                                         //1003
        NULL,                                                         //1004
        NULL,                                                         //1005
        NULL,                                                         //1006
        NULL,                                                         //1007
        NULL,                                                         //1008
        NULL,                                                         //1009
        NULL,                                                         //1010
        NULL,                                                         //1011
        NULL,                                                         //1012
        NULL,                                                         //1013
        NULL,                                                         //1014
        NULL,                                                         //1015
        NULL,                                                         //1016
        NULL,                                                         //1017
        NULL,                                                         //1018
        NULL,                                                         //1019
        NULL,                                                         //1020
        NULL,                                                         //1021
        NULL,                                                         //1022
        NULL,                                                         //1023
        NULL,                                                         //1024
        NULL,                                                         //1025
        NULL,                                                         //1026
        NULL,                                                         //1027
        NULL,                                                         //1028
        NULL,                                                         //1029
        "FORMULA : Cell Formula",                                     //1030
        NULL,                                                         //1031
        NULL,                                                         //1032
        NULL,                                                         //1033
        NULL,                                                         //1034
        NULL,                                                         //1035
        NULL,                                                         //1036
        NULL,                                                         //1037
        NULL,                                                         //1038
        NULL,                                                         //1039
        NULL,                                                         //1040
        NULL,                                                         //1041
        NULL,                                                         //1042
        NULL,                                                         //1043
        NULL,                                                         //1044
        NULL,                                                         //1045
        NULL,                                                         //1046
        NULL,                                                         //1047
        NULL,                                                         //1048
        NULL,                                                         //1049
        NULL,                                                         //1050
        NULL,                                                         //1051
        NULL,                                                         //1052
        NULL,                                                         //1053
        "FORMAT : Number Format",                                     //1054
        NULL,                                                         //1055
        NULL,                                                         //1056
        NULL,                                                         //1057
        NULL,                                                         //1058
        NULL,                                                         //1059
        NULL,                                                         //1060
        NULL,                                                         //1061
        NULL,                                                         //1062
        NULL,                                                         //1063
        NULL,                                                         //1064
        NULL,                                                         //1065
        NULL,                                                         //1066
        NULL,                                                         //1067
        NULL,                                                         //1068
        NULL,                                                         //1069
        NULL,                                                         //1070
        NULL,                                                         //1071
        NULL,                                                         //1072
        NULL,                                                         //1073
        NULL,                                                         //1074
        NULL,                                                         //1075
        NULL,                                                         //1076
        NULL,                                                         //1077
        NULL,                                                         //1078
        NULL,                                                         //1079
        NULL,                                                         //1080
        NULL,                                                         //1081
        NULL,                                                         //1082
        NULL,                                                         //1083
        NULL,                                                         //1084
        NULL,                                                         //1085
        NULL,                                                         //1086
        NULL,                                                         //1087
        NULL,                                                         //1088
        NULL,                                                         //1089
        NULL,                                                         //1090
        NULL,                                                         //1091
        NULL,                                                         //1092
        NULL,                                                         //1093
        NULL,                                                         //1094
        NULL,                                                         //1095
        NULL,                                                         //1096
        NULL,                                                         //1097
        NULL,                                                         //1098
        NULL,                                                         //1099
        NULL,                                                         //1100
        NULL,                                                         //1101
        NULL,                                                         //1102
        NULL,                                                         //1103
        NULL,                                                         //1104
        NULL,                                                         //1105
        NULL,                                                         //1106
        NULL,                                                         //1107
        NULL,                                                         //1108
        NULL,                                                         //1109
        NULL,                                                         //1110
        NULL,                                                         //1111
        NULL,                                                         //1112
        NULL,                                                         //1113
        NULL,                                                         //1114
        NULL,                                                         //1115
        NULL,                                                         //1116
        NULL,                                                         //1117
        NULL,                                                         //1118
        NULL,                                                         //1119
        NULL,                                                         //1120
        NULL,                                                         //1121
        NULL,                                                         //1122
        NULL,                                                         //1123
        NULL,                                                         //1124
        NULL,                                                         //1125
        NULL,                                                         //1126
        NULL,                                                         //1127
        NULL,                                                         //1128
        NULL,                                                         //1129
        NULL,                                                         //1130
        NULL,                                                         //1131
        NULL,                                                         //1132
        NULL,                                                         //1133
        NULL,                                                         //1134
        NULL,                                                         //1135
        NULL,                                                         //1136
        NULL,                                                         //1137
        NULL,                                                         //1138
        NULL,                                                         //1139
        NULL,                                                         //1140
        NULL,                                                         //1141
        NULL,                                                         //1142
        NULL,                                                         //1143
        NULL,                                                         //1144
        NULL,                                                         //1145
        NULL,                                                         //1146
        NULL,                                                         //1147
        NULL,                                                         //1148
        NULL,                                                         //1149
        NULL,                                                         //1150
        NULL,                                                         //1151
        NULL,                                                         //1152
        NULL,                                                         //1153
        NULL,                                                         //1154
        NULL,                                                         //1155
        NULL,                                                         //1156
        NULL,                                                         //1157
        NULL,                                                         //1158
        NULL,                                                         //1159
        NULL,                                                         //1160
        NULL,                                                         //1161
        NULL,                                                         //1162
        NULL,                                                         //1163
        NULL,                                                         //1164
        NULL,                                                         //1165
        NULL,                                                         //1166
        NULL,                                                         //1167
        NULL,                                                         //1168
        NULL,                                                         //1169
        NULL,                                                         //1170
        NULL,                                                         //1171
        NULL,                                                         //1172
        NULL,                                                         //1173
        NULL,                                                         //1174
        NULL,                                                         //1175
        NULL,                                                         //1176
        NULL,                                                         //1177
        NULL,                                                         //1178
        NULL,                                                         //1179
        NULL,                                                         //1180
        NULL,                                                         //1181
        NULL,                                                         //1182
        NULL,                                                         //1183
        NULL,                                                         //1184
        NULL,                                                         //1185
        NULL,                                                         //1186
        NULL,                                                         //1187
        NULL,                                                         //1188
        NULL,                                                         //1189
        NULL,                                                         //1190
        NULL,                                                         //1191
        NULL,                                                         //1192
        NULL,                                                         //1193
        NULL,                                                         //1194
        NULL,                                                         //1195
        NULL,                                                         //1196
        NULL,                                                         //1197
        NULL,                                                         //1198
        NULL,                                                         //1199
        NULL,                                                         //1200
        NULL,                                                         //1201
        NULL,                                                         //1202
        NULL,                                                         //1203
        NULL,                                                         //1204
        NULL,                                                         //1205
        NULL,                                                         //1206
        NULL,                                                         //1207
        NULL,                                                         //1208
        NULL,                                                         //1209
        NULL,                                                         //1210
        NULL,                                                         //1211
        NULL,                                                         //1212
        NULL,                                                         //1213
        NULL,                                                         //1214
        NULL,                                                         //1215
        NULL,                                                         //1216
        NULL,                                                         //1217
        NULL,                                                         //1218
        NULL,                                                         //1219
        NULL,                                                         //1220
        NULL,                                                         //1221
        NULL,                                                         //1222
        NULL,                                                         //1223
        NULL,                                                         //1224
        NULL,                                                         //1225
        NULL,                                                         //1226
        NULL,                                                         //1227
        NULL,                                                         //1228
        NULL,                                                         //1229
        NULL,                                                         //1230
        NULL,                                                         //1231
        NULL,                                                         //1232
        NULL,                                                         //1233
        NULL,                                                         //1234
        NULL,                                                         //1235
        NULL,                                                         //1236
        NULL,                                                         //1237
        NULL,                                                         //1238
        NULL,                                                         //1239
        NULL,                                                         //1240
        NULL,                                                         //1241
        NULL,                                                         //1242
        NULL,                                                         //1243
        NULL,                                                         //1244
        NULL,                                                         //1245
        NULL,                                                         //1246
        NULL,                                                         //1247
        NULL,                                                         //1248
        NULL,                                                         //1249
        NULL,                                                         //1250
        NULL,                                                         //1251
        NULL,                                                         //1252
        NULL,                                                         //1253
        NULL,                                                         //1254
        NULL,                                                         //1255
        NULL,                                                         //1256
        NULL,                                                         //1257
        NULL,                                                         //1258
        NULL,                                                         //1259
        NULL,                                                         //1260
        NULL,                                                         //1261
        NULL,                                                         //1262
        NULL,                                                         //1263
        NULL,                                                         //1264
        NULL,                                                         //1265
        NULL,                                                         //1266
        NULL,                                                         //1267
        NULL,                                                         //1268
        NULL,                                                         //1269
        NULL,                                                         //1270
        NULL,                                                         //1271
        NULL,                                                         //1272
        NULL,                                                         //1273
        NULL,                                                         //1274
        NULL,                                                         //1275
        NULL,                                                         //1276
        NULL,                                                         //1277
        NULL,                                                         //1278
        NULL,                                                         //1279
        NULL,                                                         //1280
        NULL,                                                         //1281
        NULL,                                                         //1282
        NULL,                                                         //1283
        NULL,                                                         //1284
        NULL,                                                         //1285
        NULL,                                                         //1286
        NULL,                                                         //1287
        NULL,                                                         //1288
        NULL,                                                         //1289
        NULL,                                                         //1290
        NULL,                                                         //1291
        NULL,                                                         //1292
        NULL,                                                         //1293
        NULL,                                                         //1294
        NULL,                                                         //1295
        NULL,                                                         //1296
        NULL,                                                         //1297
        NULL,                                                         //1298
        NULL,                                                         //1299
        NULL,                                                         //1300
        NULL,                                                         //1301
        NULL,                                                         //1302
        NULL,                                                         //1303
        NULL,                                                         //1304
        NULL,                                                         //1305
        NULL,                                                         //1306
        NULL,                                                         //1307
        NULL,                                                         //1308
        NULL,                                                         //1309
        NULL,                                                         //1310
        NULL,                                                         //1311
        NULL,                                                         //1312
        NULL,                                                         //1313
        NULL,                                                         //1314
        NULL,                                                         //1315
        NULL,                                                         //1316
        NULL,                                                         //1317
        NULL,                                                         //1318
        NULL,                                                         //1319
        NULL,                                                         //1320
        NULL,                                                         //1321
        NULL,                                                         //1322
        NULL,                                                         //1323
        NULL,                                                         //1324
        NULL,                                                         //1325
        NULL,                                                         //1326
        NULL,                                                         //1327
        NULL,                                                         //1328
        NULL,                                                         //1329
        NULL,                                                         //1330
        NULL,                                                         //1331
        NULL,                                                         //1332
        NULL,                                                         //1333
        NULL,                                                         //1334
        NULL,                                                         //1335
        NULL,                                                         //1336
        NULL,                                                         //1337
        NULL,                                                         //1338
        NULL,                                                         //1339
        NULL,                                                         //1340
        NULL,                                                         //1341
        NULL,                                                         //1342
        NULL,                                                         //1343
        NULL,                                                         //1344
        NULL,                                                         //1345
        NULL,                                                         //1346
        NULL,                                                         //1347
        NULL,                                                         //1348
        NULL,                                                         //1349
        NULL,                                                         //1350
        NULL,                                                         //1351
        NULL,                                                         //1352
        NULL,                                                         //1353
        NULL,                                                         //1354
        NULL,                                                         //1355
        NULL,                                                         //1356
        NULL,                                                         //1357
        NULL,                                                         //1358
        NULL,                                                         //1359
        NULL,                                                         //1360
        NULL,                                                         //1361
        NULL,                                                         //1362
        NULL,                                                         //1363
        NULL,                                                         //1364
        NULL,                                                         //1365
        NULL,                                                         //1366
        NULL,                                                         //1367
        NULL,                                                         //1368
        NULL,                                                         //1369
        NULL,                                                         //1370
        NULL,                                                         //1371
        NULL,                                                         //1372
        NULL,                                                         //1373
        NULL,                                                         //1374
        NULL,                                                         //1375
        NULL,                                                         //1376
        NULL,                                                         //1377
        NULL,                                                         //1378
        NULL,                                                         //1379
        NULL,                                                         //1380
        NULL,                                                         //1381
        NULL,                                                         //1382
        NULL,                                                         //1383
        NULL,                                                         //1384
        NULL,                                                         //1385
        NULL,                                                         //1386
        NULL,                                                         //1387
        NULL,                                                         //1388
        NULL,                                                         //1389
        NULL,                                                         //1390
        NULL,                                                         //1391
        NULL,                                                         //1392
        NULL,                                                         //1393
        NULL,                                                         //1394
        NULL,                                                         //1395
        NULL,                                                         //1396
        NULL,                                                         //1397
        NULL,                                                         //1398
        NULL,                                                         //1399
        NULL,                                                         //1400
        NULL,                                                         //1401
        NULL,                                                         //1402
        NULL,                                                         //1403
        NULL,                                                         //1404
        NULL,                                                         //1405
        NULL,                                                         //1406
        NULL,                                                         //1407
        NULL,                                                         //1408
        NULL,                                                         //1409
        NULL,                                                         //1410
        NULL,                                                         //1411
        NULL,                                                         //1412
        NULL,                                                         //1413
        NULL,                                                         //1414
        NULL,                                                         //1415
        NULL,                                                         //1416
        NULL,                                                         //1417
        NULL,                                                         //1418
        NULL,                                                         //1419
        NULL,                                                         //1420
        NULL,                                                         //1421
        NULL,                                                         //1422
        NULL,                                                         //1423
        NULL,                                                         //1424
        NULL,                                                         //1425
        NULL,                                                         //1426
        NULL,                                                         //1427
        NULL,                                                         //1428
        NULL,                                                         //1429
        NULL,                                                         //1430
        NULL,                                                         //1431
        NULL,                                                         //1432
        NULL,                                                         //1433
        NULL,                                                         //1434
        NULL,                                                         //1435
        NULL,                                                         //1436
        NULL,                                                         //1437
        NULL,                                                         //1438
        NULL,                                                         //1439
        NULL,                                                         //1440
        NULL,                                                         //1441
        NULL,                                                         //1442
        NULL,                                                         //1443
        NULL,                                                         //1444
        NULL,                                                         //1445
        NULL,                                                         //1446
        NULL,                                                         //1447
        NULL,                                                         //1448
        NULL,                                                         //1449
        NULL,                                                         //1450
        NULL,                                                         //1451
        NULL,                                                         //1452
        NULL,                                                         //1453
        NULL,                                                         //1454
        NULL,                                                         //1455
        NULL,                                                         //1456
        NULL,                                                         //1457
        NULL,                                                         //1458
        NULL,                                                         //1459
        NULL,                                                         //1460
        NULL,                                                         //1461
        NULL,                                                         //1462
        NULL,                                                         //1463
        NULL,                                                         //1464
        NULL,                                                         //1465
        NULL,                                                         //1466
        NULL,                                                         //1467
        NULL,                                                         //1468
        NULL,                                                         //1469
        NULL,                                                         //1470
        NULL,                                                         //1471
        NULL,                                                         //1472
        NULL,                                                         //1473
        NULL,                                                         //1474
        NULL,                                                         //1475
        NULL,                                                         //1476
        NULL,                                                         //1477
        NULL,                                                         //1478
        NULL,                                                         //1479
        NULL,                                                         //1480
        NULL,                                                         //1481
        NULL,                                                         //1482
        NULL,                                                         //1483
        NULL,                                                         //1484
        NULL,                                                         //1485
        NULL,                                                         //1486
        NULL,                                                         //1487
        NULL,                                                         //1488
        NULL,                                                         //1489
        NULL,                                                         //1490
        NULL,                                                         //1491
        NULL,                                                         //1492
        NULL,                                                         //1493
        NULL,                                                         //1494
        NULL,                                                         //1495
        NULL,                                                         //1496
        NULL,                                                         //1497
        NULL,                                                         //1498
        NULL,                                                         //1499
        NULL,                                                         //1500
        NULL,                                                         //1501
        NULL,                                                         //1502
        NULL,                                                         //1503
        NULL,                                                         //1504
        NULL,                                                         //1505
        NULL,                                                         //1506
        NULL,                                                         //1507
        NULL,                                                         //1508
        NULL,                                                         //1509
        NULL,                                                         //1510
        NULL,                                                         //1511
        NULL,                                                         //1512
        NULL,                                                         //1513
        NULL,                                                         //1514
        NULL,                                                         //1515
        NULL,                                                         //1516
        NULL,                                                         //1517
        NULL,                                                         //1518
        NULL,                                                         //1519
        NULL,                                                         //1520
        NULL,                                                         //1521
        NULL,                                                         //1522
        NULL,                                                         //1523
        NULL,                                                         //1524
        NULL,                                                         //1525
        NULL,                                                         //1526
        NULL,                                                         //1527
        NULL,                                                         //1528
        NULL,                                                         //1529
        NULL,                                                         //1530
        NULL,                                                         //1531
        NULL,                                                         //1532
        NULL,                                                         //1533
        NULL,                                                         //1534
        NULL,                                                         //1535
        NULL,                                                         //1536
        NULL,                                                         //1537
        NULL,                                                         //1538
        NULL,                                                         //1539
        NULL,                                                         //1540
        NULL,                                                         //1541
        NULL,                                                         //1542
        NULL,                                                         //1543
        NULL,                                                         //1544
        NULL,                                                         //1545
        NULL,                                                         //1546
        NULL,                                                         //1547
        NULL,                                                         //1548
        NULL,                                                         //1549
        NULL,                                                         //1550
        NULL,                                                         //1551
        NULL,                                                         //1552
        NULL,                                                         //1553
        NULL,                                                         //1554
        NULL,                                                         //1555
        NULL,                                                         //1556
        NULL,                                                         //1557
        NULL,                                                         //1558
        NULL,                                                         //1559
        NULL,                                                         //1560
        NULL,                                                         //1561
        NULL,                                                         //1562
        NULL,                                                         //1563
        NULL,                                                         //1564
        NULL,                                                         //1565
        NULL,                                                         //1566
        NULL,                                                         //1567
        NULL,                                                         //1568
        NULL,                                                         //1569
        NULL,                                                         //1570
        NULL,                                                         //1571
        NULL,                                                         //1572
        NULL,                                                         //1573
        NULL,                                                         //1574
        NULL,                                                         //1575
        NULL,                                                         //1576
        NULL,                                                         //1577
        NULL,                                                         //1578
        NULL,                                                         //1579
        NULL,                                                         //1580
        NULL,                                                         //1581
        NULL,                                                         //1582
        NULL,                                                         //1583
        NULL,                                                         //1584
        NULL,                                                         //1585
        NULL,                                                         //1586
        NULL,                                                         //1587
        NULL,                                                         //1588
        NULL,                                                         //1589
        NULL,                                                         //1590
        NULL,                                                         //1591
        NULL,                                                         //1592
        NULL,                                                         //1593
        NULL,                                                         //1594
        NULL,                                                         //1595
        NULL,                                                         //1596
        NULL,                                                         //1597
        NULL,                                                         //1598
        NULL,                                                         //1599
        NULL,                                                         //1600
        NULL,                                                         //1601
        NULL,                                                         //1602
        NULL,                                                         //1603
        NULL,                                                         //1604
        NULL,                                                         //1605
        NULL,                                                         //1606
        NULL,                                                         //1607
        NULL,                                                         //1608
        NULL,                                                         //1609
        NULL,                                                         //1610
        NULL,                                                         //1611
        NULL,                                                         //1612
        NULL,                                                         //1613
        NULL,                                                         //1614
        NULL,                                                         //1615
        NULL,                                                         //1616
        NULL,                                                         //1617
        NULL,                                                         //1618
        NULL,                                                         //1619
        NULL,                                                         //1620
        NULL,                                                         //1621
        NULL,                                                         //1622
        NULL,                                                         //1623
        NULL,                                                         //1624
        NULL,                                                         //1625
        NULL,                                                         //1626
        NULL,                                                         //1627
        NULL,                                                         //1628
        NULL,                                                         //1629
        NULL,                                                         //1630
        NULL,                                                         //1631
        NULL,                                                         //1632
        NULL,                                                         //1633
        NULL,                                                         //1634
        NULL,                                                         //1635
        NULL,                                                         //1636
        NULL,                                                         //1637
        NULL,                                                         //1638
        NULL,                                                         //1639
        NULL,                                                         //1640
        NULL,                                                         //1641
        NULL,                                                         //1642
        NULL,                                                         //1643
        NULL,                                                         //1644
        NULL,                                                         //1645
        NULL,                                                         //1646
        NULL,                                                         //1647
        NULL,                                                         //1648
        NULL,                                                         //1649
        NULL,                                                         //1650
        NULL,                                                         //1651
        NULL,                                                         //1652
        NULL,                                                         //1653
        NULL,                                                         //1654
        NULL,                                                         //1655
        NULL,                                                         //1656
        NULL,                                                         //1657
        NULL,                                                         //1658
        NULL,                                                         //1659
        NULL,                                                         //1660
        NULL,                                                         //1661
        NULL,                                                         //1662
        NULL,                                                         //1663
        NULL,                                                         //1664
        NULL,                                                         //1665
        NULL,                                                         //1666
        NULL,                                                         //1667
        NULL,                                                         //1668
        NULL,                                                         //1669
        NULL,                                                         //1670
        NULL,                                                         //1671
        NULL,                                                         //1672
        NULL,                                                         //1673
        NULL,                                                         //1674
        NULL,                                                         //1675
        NULL,                                                         //1676
        NULL,                                                         //1677
        NULL,                                                         //1678
        NULL,                                                         //1679
        NULL,                                                         //1680
        NULL,                                                         //1681
        NULL,                                                         //1682
        NULL,                                                         //1683
        NULL,                                                         //1684
        NULL,                                                         //1685
        NULL,                                                         //1686
        NULL,                                                         //1687
        NULL,                                                         //1688
        NULL,                                                         //1689
        NULL,                                                         //1690
        NULL,                                                         //1691
        NULL,                                                         //1692
        NULL,                                                         //1693
        NULL,                                                         //1694
        NULL,                                                         //1695
        NULL,                                                         //1696
        NULL,                                                         //1697
        NULL,                                                         //1698
        NULL,                                                         //1699
        NULL,                                                         //1700
        NULL,                                                         //1701
        NULL,                                                         //1702
        NULL,                                                         //1703
        NULL,                                                         //1704
        NULL,                                                         //1705
        NULL,                                                         //1706
        NULL,                                                         //1707
        NULL,                                                         //1708
        NULL,                                                         //1709
        NULL,                                                         //1710
        NULL,                                                         //1711
        NULL,                                                         //1712
        NULL,                                                         //1713
        NULL,                                                         //1714
        NULL,                                                         //1715
        NULL,                                                         //1716
        NULL,                                                         //1717
        NULL,                                                         //1718
        NULL,                                                         //1719
        NULL,                                                         //1720
        NULL,                                                         //1721
        NULL,                                                         //1722
        NULL,                                                         //1723
        NULL,                                                         //1724
        NULL,                                                         //1725
        NULL,                                                         //1726
        NULL,                                                         //1727
        NULL,                                                         //1728
        NULL,                                                         //1729
        NULL,                                                         //1730
        NULL,                                                         //1731
        NULL,                                                         //1732
        NULL,                                                         //1733
        NULL,                                                         //1734
        NULL,                                                         //1735
        NULL,                                                         //1736
        NULL,                                                         //1737
        NULL,                                                         //1738
        NULL,                                                         //1739
        NULL,                                                         //1740
        NULL,                                                         //1741
        NULL,                                                         //1742
        NULL,                                                         //1743
        NULL,                                                         //1744
        NULL,                                                         //1745
        NULL,                                                         //1746
        NULL,                                                         //1747
        NULL,                                                         //1748
        NULL,                                                         //1749
        NULL,                                                         //1750
        NULL,                                                         //1751
        NULL,                                                         //1752
        NULL,                                                         //1753
        NULL,                                                         //1754
        NULL,                                                         //1755
        NULL,                                                         //1756
        NULL,                                                         //1757
        NULL,                                                         //1758
        NULL,                                                         //1759
        NULL,                                                         //1760
        NULL,                                                         //1761
        NULL,                                                         //1762
        NULL,                                                         //1763
        NULL,                                                         //1764
        NULL,                                                         //1765
        NULL,                                                         //1766
        NULL,                                                         //1767
        NULL,                                                         //1768
        NULL,                                                         //1769
        NULL,                                                         //1770
        NULL,                                                         //1771
        NULL,                                                         //1772
        NULL,                                                         //1773
        NULL,                                                         //1774
        NULL,                                                         //1775
        NULL,                                                         //1776
        NULL,                                                         //1777
        NULL,                                                         //1778
        NULL,                                                         //1779
        NULL,                                                         //1780
        NULL,                                                         //1781
        NULL,                                                         //1782
        NULL,                                                         //1783
        NULL,                                                         //1784
        NULL,                                                         //1785
        NULL,                                                         //1786
        NULL,                                                         //1787
        NULL,                                                         //1788
        NULL,                                                         //1789
        NULL,                                                         //1790
        NULL,                                                         //1791
        NULL,                                                         //1792
        NULL,                                                         //1793
        NULL,                                                         //1794
        NULL,                                                         //1795
        NULL,                                                         //1796
        NULL,                                                         //1797
        NULL,                                                         //1798
        NULL,                                                         //1799
        NULL,                                                         //1800
        NULL,                                                         //1801
        NULL,                                                         //1802
        NULL,                                                         //1803
        NULL,                                                         //1804
        NULL,                                                         //1805
        NULL,                                                         //1806
        NULL,                                                         //1807
        NULL,                                                         //1808
        NULL,                                                         //1809
        NULL,                                                         //1810
        NULL,                                                         //1811
        NULL,                                                         //1812
        NULL,                                                         //1813
        NULL,                                                         //1814
        NULL,                                                         //1815
        NULL,                                                         //1816
        NULL,                                                         //1817
        NULL,                                                         //1818
        NULL,                                                         //1819
        NULL,                                                         //1820
        NULL,                                                         //1821
        NULL,                                                         //1822
        NULL,                                                         //1823
        NULL,                                                         //1824
        NULL,                                                         //1825
        NULL,                                                         //1826
        NULL,                                                         //1827
        NULL,                                                         //1828
        NULL,                                                         //1829
        NULL,                                                         //1830
        NULL,                                                         //1831
        NULL,                                                         //1832
        NULL,                                                         //1833
        NULL,                                                         //1834
        NULL,                                                         //1835
        NULL,                                                         //1836
        NULL,                                                         //1837
        NULL,                                                         //1838
        NULL,                                                         //1839
        NULL,                                                         //1840
        NULL,                                                         //1841
        NULL,                                                         //1842
        NULL,                                                         //1843
        NULL,                                                         //1844
        NULL,                                                         //1845
        NULL,                                                         //1846
        NULL,                                                         //1847
        NULL,                                                         //1848
        NULL,                                                         //1849
        NULL,                                                         //1850
        NULL,                                                         //1851
        NULL,                                                         //1852
        NULL,                                                         //1853
        NULL,                                                         //1854
        NULL,                                                         //1855
        NULL,                                                         //1856
        NULL,                                                         //1857
        NULL,                                                         //1858
        NULL,                                                         //1859
        NULL,                                                         //1860
        NULL,                                                         //1861
        NULL,                                                         //1862
        NULL,                                                         //1863
        NULL,                                                         //1864
        NULL,                                                         //1865
        NULL,                                                         //1866
        NULL,                                                         //1867
        NULL,                                                         //1868
        NULL,                                                         //1869
        NULL,                                                         //1870
        NULL,                                                         //1871
        NULL,                                                         //1872
        NULL,                                                         //1873
        NULL,                                                         //1874
        NULL,                                                         //1875
        NULL,                                                         //1876
        NULL,                                                         //1877
        NULL,                                                         //1878
        NULL,                                                         //1879
        NULL,                                                         //1880
        NULL,                                                         //1881
        NULL,                                                         //1882
        NULL,                                                         //1883
        NULL,                                                         //1884
        NULL,                                                         //1885
        NULL,                                                         //1886
        NULL,                                                         //1887
        NULL,                                                         //1888
        NULL,                                                         //1889
        NULL,                                                         //1890
        NULL,                                                         //1891
        NULL,                                                         //1892
        NULL,                                                         //1893
        NULL,                                                         //1894
        NULL,                                                         //1895
        NULL,                                                         //1896
        NULL,                                                         //1897
        NULL,                                                         //1898
        NULL,                                                         //1899
        NULL,                                                         //1900
        NULL,                                                         //1901
        NULL,                                                         //1902
        NULL,                                                         //1903
        NULL,                                                         //1904
        NULL,                                                         //1905
        NULL,                                                         //1906
        NULL,                                                         //1907
        NULL,                                                         //1908
        NULL,                                                         //1909
        NULL,                                                         //1910
        NULL,                                                         //1911
        NULL,                                                         //1912
        NULL,                                                         //1913
        NULL,                                                         //1914
        NULL,                                                         //1915
        NULL,                                                         //1916
        NULL,                                                         //1917
        NULL,                                                         //1918
        NULL,                                                         //1919
        NULL,                                                         //1920
        NULL,                                                         //1921
        NULL,                                                         //1922
        NULL,                                                         //1923
        NULL,                                                         //1924
        NULL,                                                         //1925
        NULL,                                                         //1926
        NULL,                                                         //1927
        NULL,                                                         //1928
        NULL,                                                         //1929
        NULL,                                                         //1930
        NULL,                                                         //1931
        NULL,                                                         //1932
        NULL,                                                         //1933
        NULL,                                                         //1934
        NULL,                                                         //1935
        NULL,                                                         //1936
        NULL,                                                         //1937
        NULL,                                                         //1938
        NULL,                                                         //1939
        NULL,                                                         //1940
        NULL,                                                         //1941
        NULL,                                                         //1942
        NULL,                                                         //1943
        NULL,                                                         //1944
        NULL,                                                         //1945
        NULL,                                                         //1946
        NULL,                                                         //1947
        NULL,                                                         //1948
        NULL,                                                         //1949
        NULL,                                                         //1950
        NULL,                                                         //1951
        NULL,                                                         //1952
        NULL,                                                         //1953
        NULL,                                                         //1954
        NULL,                                                         //1955
        NULL,                                                         //1956
        NULL,                                                         //1957
        NULL,                                                         //1958
        NULL,                                                         //1959
        NULL,                                                         //1960
        NULL,                                                         //1961
        NULL,                                                         //1962
        NULL,                                                         //1963
        NULL,                                                         //1964
        NULL,                                                         //1965
        NULL,                                                         //1966
        NULL,                                                         //1967
        NULL,                                                         //1968
        NULL,                                                         //1969
        NULL,                                                         //1970
        NULL,                                                         //1971
        NULL,                                                         //1972
        NULL,                                                         //1973
        NULL,                                                         //1974
        NULL,                                                         //1975
        NULL,                                                         //1976
        NULL,                                                         //1977
        NULL,                                                         //1978
        NULL,                                                         //1979
        NULL,                                                         //1980
        NULL,                                                         //1981
        NULL,                                                         //1982
        NULL,                                                         //1983
        NULL,                                                         //1984
        NULL,                                                         //1985
        NULL,                                                         //1986
        NULL,                                                         //1987
        NULL,                                                         //1988
        NULL,                                                         //1989
        NULL,                                                         //1990
        NULL,                                                         //1991
        NULL,                                                         //1992
        NULL,                                                         //1993
        NULL,                                                         //1994
        NULL,                                                         //1995
        NULL,                                                         //1996
        NULL,                                                         //1997
        NULL,                                                         //1998
        NULL,                                                         //1999
        NULL,                                                         //2000
        NULL,                                                         //2001
        NULL,                                                         //2002
        NULL,                                                         //2003
        NULL,                                                         //2004
        NULL,                                                         //2005
        NULL,                                                         //2006
        NULL,                                                         //2007
        NULL,                                                         //2008
        NULL,                                                         //2009
        NULL,                                                         //2010
        NULL,                                                         //2011
        NULL,                                                         //2012
        NULL,                                                         //2013
        NULL,                                                         //2014
        NULL,                                                         //2015
        NULL,                                                         //2016
        NULL,                                                         //2017
        NULL,                                                         //2018
        NULL,                                                         //2019
        NULL,                                                         //2020
        NULL,                                                         //2021
        NULL,                                                         //2022
        NULL,                                                         //2023
        NULL,                                                         //2024
        NULL,                                                         //2025
        NULL,                                                         //2026
        NULL,                                                         //2027
        NULL,                                                         //2028
        NULL,                                                         //2029
        NULL,                                                         //2030
        NULL,                                                         //2031
        NULL,                                                         //2032
        NULL,                                                         //2033
        NULL,                                                         //2034
        NULL,                                                         //2035
        NULL,                                                         //2036
        NULL,                                                         //2037
        NULL,                                                         //2038
        NULL,                                                         //2039
        NULL,                                                         //2040
        NULL,                                                         //2041
        NULL,                                                         //2042
        NULL,                                                         //2043
        NULL,                                                         //2044
        NULL,                                                         //2045
        NULL,                                                         //2046
        NULL,                                                         //2047
        "HLINKTOOLTIP : Hyperlink Tooltip",                           //2048
        "WEBPUB : Web Publish Item",                                  //2049
        "QSISXTAG : PivotTable and Query Table Extensions",           //2050
        "DBQUERYEXT : Database Query Extensions",                     //2051
        "EXTSTRING :  FRT String",                                    //2052
        "TXTQUERY : Text Query Information",                          //2053
        "QSIR : Query Table Formatting",                              //2054
        "QSIF : Query Table Field Formatting",                        //2055
        NULL,                                                         //2056
        "BOF : Beginning of File",                                    //2057
        "OLEDBCONN : OLE Database Connection",                        //2058
        "WOPT : Web Options",                                         //2059
        "SXVIEWEX : Pivot Table OLAP Extensions",                     //2060
        "SXTH : PivotTable OLAP Hierarchy",                           //2061
        "SXPIEX : OLAP Page Item Extensions",                         //2062
        "SXVDTEX : View Dimension OLAP Extensions",                   //2063
        "SXVIEWEX9 : Pivot Table Extensions",                         //2064
        NULL,                                                         //2065
        "CONTINUEFRT : Continued  FRT",                               //2066
        "REALTIMEDATA : Real-Time Data (RTD)",                        //2067
        NULL,                                                         //2068
        NULL,                                                         //2069
        NULL,                                                         //2070
        NULL,                                                         //2071
        NULL,                                                         //2072
        NULL,                                                         //2073
        NULL,                                                         //2074
        NULL,                                                         //2075
        NULL,                                                         //2076
        NULL,                                                         //2077
        NULL,                                                         //2078
        NULL,                                                         //2079
        NULL,                                                         //2080
        NULL,                                                         //2081
        NULL,                                                         //2082
        NULL,                                                         //2083
        NULL,                                                         //2084
        NULL,                                                         //2085
        NULL,                                                         //2086
        NULL,                                                         //2087
        NULL,                                                         //2088
        NULL,                                                         //2089
        NULL,                                                         //2090
        NULL,                                                         //2091
        NULL,                                                         //2092
        NULL,                                                         //2093
        NULL,                                                         //2094
        NULL,                                                         //2095
        NULL,                                                         //2096
        NULL,                                                         //2097
        NULL,                                                         //2098
        NULL,                                                         //2099
        NULL,                                                         //2100
        NULL,                                                         //2101
        NULL,                                                         //2102
        NULL,                                                         //2103
        NULL,                                                         //2104
        NULL,                                                         //2105
        NULL,                                                         //2106
        NULL,                                                         //2107
        NULL,                                                         //2108
        NULL,                                                         //2109
        NULL,                                                         //2110
        NULL,                                                         //2111
        NULL,                                                         //2112
        NULL,                                                         //2113
        NULL,                                                         //2114
        NULL,                                                         //2115
        NULL,                                                         //2116
        NULL,                                                         //2117
        NULL,                                                         //2118
        NULL,                                                         //2119
        NULL,                                                         //2120
        NULL,                                                         //2121
        NULL,                                                         //2122
        NULL,                                                         //2123
        NULL,                                                         //2124
        NULL,                                                         //2125
        NULL,                                                         //2126
        NULL,                                                         //2127
        NULL,                                                         //2128
        NULL,                                                         //2129
        NULL,                                                         //2130
        NULL,                                                         //2131
        NULL,                                                         //2132
        NULL,                                                         //2133
        NULL,                                                         //2134
        NULL,                                                         //2135
        NULL,                                                         //2136
        NULL,                                                         //2137
        NULL,                                                         //2138
        NULL,                                                         //2139
        NULL,                                                         //2140
        NULL,                                                         //2141
        NULL,                                                         //2142
        NULL,                                                         //2143
        NULL,                                                         //2144
        NULL,                                                         //2145
        "SHEETEXT : Extra Sheet Info",                                //2146
        "BOOKEXT : Extra Book Info",                                  //2147
        "SXADDL : Pivot Table Additional Info",                       //2148
        "CRASHRECERR : Crash Recovery Error",                         //2149
        "HFPicture : Header / Footer Picture",                        //2150
        "FEATHEADR : Shared Feature Header",                          //2151
        "FEAT : Shared Feature Record",                               //2152
        NULL,                                                         //2153
        "DATALABEXT : Chart Data Label Extension",                    //2154
        "DATALABEXTCONTENTS : Chart Data Label Extension Contents",   //2155
        "CELLWATCH : Cell Watch",                                     //2156
        "FEATINFO : Shared Feature Info Record",                      //2157
        NULL,                                                         //2158
        NULL,                                                         //2159
        NULL,                                                         //2160
        "FEATHEADR11 : Shared Feature Header 11",                     //2161
        "FEAT11 : Shared Feature 11 Record",                          //2162
        "FEATINFO11 : Shared Feature Info 11 Record",                 //2163
        "DROPDOWNOBJIDS : Drop Down Object",                          //2164
        "CONTINUEFRT11 : Continue  FRT 11",                           //2165
        "DCONN : Data Connection",                                    //2166
        "LIST12 : Extra Table Data Introduced in Excel 2007",         //2167
        "FEAT12 : Shared Feature 12 Record",                          //2168
        "CONDFMT12 : Conditional Formatting Range Information 12",    //2169
        "CF12 : Conditional Formatting Condition 12",                 //2170
        "CFEX : Conditional Formatting Extension",                    //2171
        "XFCRC : XF Extensions Checksum",                             //2172
        "XFEXT : XF Extension",                                       //2173
        "EZFILTER12 : AutoFilter Data Introduced in Excel 2007",      //2174
        "CONTINUEFRT12 : Continue FRT 12",                            //2175
        NULL,                                                         //2176
        "SXADDL12 : Additional Workbook Connections Information",     //2177
        NULL,                                                         //2178
        NULL,                                                         //2179
        "MDTINFO : Information about a Metadata Type",                //2180
        "MDXSTR : MDX Metadata String",                               //2181
        "MDXTUPLE : Tuple MDX Metadata",                              //2182
        "MDXSET : Set MDX Metadata",                                  //2183
        "MDXPROP : Member Property MDX Metadata",                     //2184
        "MDXKPI : Key Performance Indicator MDX Metadata",            //2185
        "MDTB : Block of Metadata Records",                           //2186
        "PLV : Page Layout View Settings in Excel 2007",              //2187
        "COMPAT12 : Compatibility Checker 12",                        //2188
        "DXF : Differential XF",                                      //2189
        "TABLESTYLES : Table Styles",                                 //2190
        "TABLESTYLE : Table Style",                                   //2191
        "TABLESTYLEELEMENT : Table Style Element",                    //2192
        NULL,                                                         //2193
        "STYLEEXT : Named Cell Style Extension",                      //2194
        "NAMEPUBLISH : Publish To Excel Server Data for Name",        //2195
        "NAMECMT : Name Comment",                                     //2196
        "SORTDATA12 : Sort Data 12",                                  //2197
        "THEME : Theme",                                              //2198
        "GUIDTYPELIB : VB Project Typelib GUID",                      //2199
        "FNGRP12 : Function Group",                                   //2200
        "NAMEFNGRP12 : Extra Function Group",                         //2201
        "MTRSETTINGS : Multi-Threaded Calculation Settings",          //2202
        "COMPRESSPICTURES : Automatic Picture Compression Mode",      //2203
        "HEADERFOOTER : Header Footer",                               //2204
        NULL,                                                         //2205
        NULL,                                                         //2206
        NULL,                                                         //2207
        NULL,                                                         //2208
        NULL,                                                         //2209
        NULL,                                                         //2210
        "FORCEFULLCALCULATION : Force Full Calculation Settings",     //2211
        NULL,                                                         //2212
        NULL,                                                         //2213
        NULL,                                                         //2214
        NULL,                                                         //2215
        NULL,                                                         //2216
        NULL,                                                         //2217
        NULL,                                                         //2218
        NULL,                                                         //2219
        NULL,                                                         //2220
        NULL,                                                         //2221
        NULL,                                                         //2222
        NULL,                                                         //2223
        NULL,                                                         //2224
        NULL,                                                         //2225
        NULL,                                                         //2226
        NULL,                                                         //2227
        NULL,                                                         //2228
        NULL,                                                         //2229
        NULL,                                                         //2230
        NULL,                                                         //2231
        NULL,                                                         //2232
        NULL,                                                         //2233
        NULL,                                                         //2234
        NULL,                                                         //2235
        NULL,                                                         //2236
        NULL,                                                         //2237
        NULL,                                                         //2238
        NULL,                                                         //2239
        NULL,                                                         //2240
        "LISTOBJ : List Object",                                      //2241
        "LISTFIELD : List Field",                                     //2242
        "LISTDV : List Data Validation",                              //2243
        "LISTCONDFMT : List Conditional Formatting",                  //2244
        "LISTCF : List Cell Formatting",                              //2245
        "FMQRY : Filemaker queries",                                  //2246
        "FMSQRY : File maker queries",                                //2247
        "PLV : Page Layout View in Mac Excel 11",                     //2248
        "LNEXT : Extension information for borders in Mac Office 11", //2249
        "MKREXT : Extension information for markers in Mac Office 11",//2250
};

char *FUNCTIONS[] = {
    "COUNT",                                             //0
    "IF",                                                //1
    "ISNA",                                              //2
    "ISERROR",                                           //3
    "SUM",                                               //4
    "AVERAGE",                                           //5
    "MIN",                                               //6
    "MAX",                                               //7
    "ROW",                                               //8
    "COLUMN",                                            //9
    "NA",                                                //10
    "NPV",                                               //11
    "STDEV",                                             //12
    "DOLLAR",                                            //13
    "FIXED",                                             //14
    "SIN",                                               //15
    "COS",                                               //16
    "TAN",                                               //17
    "ATAN",                                              //18
    "PI",                                                //19
    "SQRT",                                              //20
    "EXP",                                               //21
    "LN",                                                //22
    "LOG10",                                             //23
    "ABS",                                               //24
    "INT",                                               //25
    "SIGN",                                              //26
    "ROUND",                                             //27
    "LOOKUP",                                            //28
    "INDEX",                                             //29
    "REPT",                                              //30
    "MID",                                               //31
    "LEN",                                               //32
    "VALUE",                                             //33
    "TRUE",                                              //34
    "FALSE",                                             //35
    "AND",                                               //36
    "OR",                                                //37
    "NOT",                                               //38
    "MOD",                                               //39
    "DCOUNT",                                            //40
    "DSUM",                                              //41
    "DAVERAGE",                                          //42
    "DMIN",                                              //43
    "DMAX",                                              //44
    "DSTDEV",                                            //45
    "VAR",                                               //46
    "DVAR",                                              //47
    "TEXT",                                              //48
    "LINEST",                                            //49
    "TREND",                                             //50
    "LOGEST",                                            //51
    "GROWTH",                                            //52
    "GOTO",                                              //53
    "HALT",                                              //54
    "RETURN",                                            //55
    "PV",                                                //56
    "FV",                                                //57
    "NPER",                                              //58
    "PMT",                                               //59
    "RATE",                                              //60
    "MIRR",                                              //61
    "IRR",                                               //62
    "RAND",                                              //63
    "MATCH",                                             //64
    "DATE",                                              //65
    "TIME",                                              //66
    "DAY",                                               //67
    "MONTH",                                             //68
    "YEAR",                                              //69
    "WEEKDAY",                                           //70
    "HOUR",                                              //71
    "MINUTE",                                            //72
    "SECOND",                                            //73
    "NOW",                                               //74
    "AREAS",                                             //75
    "ROWS",                                              //76
    "COLUMNS",                                           //77
    "OFFSET",                                            //78
    "ABSREF",                                            //79
    "RELREF",                                            //80
    "ARGUMENT",                                          //81
    "SEARCH",                                            //82
    "TRANSPOSE",                                         //83
    "ERROR",                                             //84
    "STEP",                                              //85
    "TYPE",                                              //86
    "ECHO",                                              //87
    "SET.NAME",                                          //88
    "CALLER",                                            //89
    "DEREF",                                             //90
    "WINDOWS",                                           //91
    "SERIES",                                            //92
    "DOCUMENTS",                                         //93
    "ACTIVE.CELL",                                       //94
    "SELECTION",                                         //95
    "RESULT",                                            //96
    "ATAN2",                                             //97
    "ASIN",                                              //98
    "ACOS",                                              //99
    "CHOOSE",                                            //100
    "HLOOKUP",                                           //101
    "VLOOKUP",                                           //102
    "LINKS",                                             //103
    "INPUT",                                             //104
    "ISREF",                                             //105
    "GET.FORMULA",                                       //106
    "GET.NAME",                                          //107
    "SET.VALUE",                                         //108
    "LOG",                                               //109
    "EXEC",                                              //110
    "CHAR",                                              //111
    "LOWER",                                             //112
    "UPPER",                                             //113
    "PROPER",                                            //114
    "LEFT",                                              //115
    "RIGHT",                                             //116
    "EXACT",                                             //117
    "TRIM",                                              //118
    "REPLACE",                                           //119
    "SUBSTITUTE",                                        //120
    "CODE",                                              //121
    "NAMES",                                             //122
    "DIRECTORY",                                         //123
    "FIND",                                              //124
    "CELL",                                              //125
    "ISERR",                                             //126
    "ISTEXT",                                            //127
    "ISNUMBER",                                          //128
    "ISBLANK",                                           //129
    "T",                                                 //130
    "N",                                                 //131
    "FOPEN",                                             //132
    "FCLOSE",                                            //133
    "FSIZE",                                             //134
    "FREADLN",                                           //135
    "FREAD",                                             //136
    "FWRITELN",                                          //137
    "FWRITE",                                            //138
    "FPOS",                                              //139
    "DATEVALUE",                                         //140
    "TIMEVALUE",                                         //141
    "SLN",                                               //142
    "SYD",                                               //143
    "DDB",                                               //144
    "GET.DEF",                                           //145
    "REFTEXT",                                           //146
    "TEXTREF",                                           //147
    "INDIRECT",                                          //148
    "REGISTER",                                          //149
    "CALL",                                              //150
    "ADD.BAR",                                           //151
    "ADD.MENU",                                          //152
    "ADD.COMMAND",                                       //153
    "ENABLE.COMMAND",                                    //154
    "CHECK.COMMAND",                                     //155
    "RENAME.COMMAND",                                    //156
    "SHOW.BAR",                                          //157
    "DELETE.MENU",                                       //158
    "DELETE.COMMAND",                                    //159
    "GET.CHART.ITEM",                                    //160
    "DIALOG.BOX",                                        //161
    "CLEAN",                                             //162
    "MDETERM",                                           //163
    "MINVERSE",                                          //164
    "MMULT",                                             //165
    "FILES",                                             //166
    "IPMT",                                              //167
    "PPMT",                                              //168
    "COUNTA",                                            //169
    "CANCEL.KEY",                                        //170
    "FOR",                                               //171
    "WHILE",                                             //172
    "BREAK",                                             //173
    "NEXT",                                              //174
    "INITIATE",                                          //175
    "REQUEST",                                           //176
    "POKE",                                              //177
    "EXECUTE",                                           //178
    "TERMINATE",                                         //179
    "RESTART",                                           //180
    "HELP",                                              //181
    "GET.BAR",                                           //182
    "PRODUCT",                                           //183
    "FACT",                                              //184
    "GET.CELL",                                          //185
    "GET.WORKSPACE",                                     //186
    "GET.WINDOW",                                        //187
    "GET.DOCUMENT",                                      //188
    "DPRODUCT",                                          //189
    "ISNONTEXT",                                         //190
    "GET.NOTE",                                          //191
    "NOTE",                                              //192
    "STDEVP",                                            //193
    "VARP",                                              //194
    "DSTDEVP",                                           //195
    "DVARP",                                             //196
    "TRUNC",                                             //197
    "ISLOGICAL",                                         //198
    "DCOUNTA",                                           //199
    "DELETE.BAR",                                        //200
    "UNREGISTER",                                        //201
    NULL,
    NULL,
    "USDOLLAR",                                          //204
    "FINDB",                                             //205
    "SEARCHB",                                           //206
    "REPLACEB",                                          //207
    "LEFTB",                                             //208
    "RIGHTB",                                            //209
    "MIDB",                                              //210
    "LENB",                                              //211
    "ROUNDUP",                                           //212
    "ROUNDDOWN",                                         //213
    "ASC",                                               //214
    "DBCS",                                              //215
    "RANK",                                              //216
    NULL,
    NULL,
    "ADDRESS",                                           //219
    "DAYS360",                                           //220
    "TODAY",                                             //221
    "VDB",                                               //222
    "ELSE",                                              //223
    "ELSE.IF",                                           //224
    "END.IF",                                            //225
    "FOR.CELL",                                          //226
    "MEDIAN",                                            //227
    "SUMPRODUCT",                                        //228
    "SINH",                                              //229
    "COSH",                                              //230
    "TANH",                                              //231
    "ASINH",                                             //232
    "ACOSH",                                             //233
    "ATANH",                                             //234
    "DGET",                                              //235
    "CREATE.OBJECT",                                     //236
    "VOLATILE",                                          //237
    "LAST.ERROR",                                        //238
    "CUSTOM.UNDO",                                       //239
    "CUSTOM.REPEAT",                                     //240
    "FORMULA.CONVERT",                                   //241
    "GET.LINK.INFO",                                     //242
    "TEXT.BOX",                                          //243
    "INFO",                                              //244
    "GROUP",                                             //245
    "GET.OBJECT",                                        //246
    "DB",                                                //247
    "PAUSE",                                             //248
    NULL,
    NULL,
    "RESUME",                                            //251
    "FREQUENCY",                                         //252
    "ADD.TOOLBAR",                                       //253
    "DELETE.TOOLBAR",                                    //254
    "User Defined Function",                             //255
    "RESET.TOOLBAR",                                     //256
    "EVALUATE",                                          //257
    "GET.TOOLBAR",                                       //258
    "GET.TOOL",                                          //259
    "SPELLING.CHECK",                                    //260
    "ERROR.TYPE",                                        //261
    "APP.TITLE",                                         //262
    "WINDOW.TITLE",                                      //263
    "SAVE.TOOLBAR",                                      //264
    "ENABLE.TOOL",                                       //265
    "PRESS.TOOL",                                        //266
    "REGISTER.ID",                                       //267
    "GET.WORKBOOK",                                      //268
    "AVEDEV",                                            //269
    "BETADIST",                                          //270
    "GAMMALN",                                           //271
    "BETAINV",                                           //272
    "BINOMDIST",                                         //273
    "CHIDIST",                                           //274
    "CHIINV",                                            //275
    "COMBIN",                                            //276
    "CONFIDENCE",                                        //277
    "CRITBINOM",                                         //278
    "EVEN",                                              //279
    "EXPONDIST",                                         //280
    "FDIST",                                             //281
    "FINV",                                              //282
    "FISHER",                                            //283
    "FISHERINV",                                         //284
    "FLOOR",                                             //285
    "GAMMADIST",                                         //286
    "GAMMAINV",                                          //287
    "CEILING",                                           //288
    "HYPGEOMDIST",                                       //289
    "LOGNORMDIST",                                       //290
    "LOGINV",                                            //291
    "NEGBINOMDIST",                                      //292
    "NORMDIST",                                          //293
    "NORMSDIST",                                         //294
    "NORMINV",                                           //295
    "NORMSINV",                                          //296
    "STANDARDIZE",                                       //297
    "ODD",                                               //298
    "PERMUT",                                            //299
    "POISSON",                                           //300
    "TDIST",                                             //301
    "WEIBULL",                                           //302
    "SUMXMY2",                                           //303
    "SUMX2MY2",                                          //304
    "SUMX2PY2",                                          //305
    "CHITEST",                                           //306
    "CORREL",                                            //307
    "COVAR",                                             //308
    "FORECAST",                                          //309
    "FTEST",                                             //310
    "INTERCEPT",                                         //311
    "PEARSON",                                           //312
    "RSQ",                                               //313
    "STEYX",                                             //314
    "SLOPE",                                             //315
    "TTEST",                                             //316
    "PROB",                                              //317
    "DEVSQ",                                             //318
    "GEOMEAN",                                           //319
    "HARMEAN",                                           //320
    "SUMSQ",                                             //321
    "KURT",                                              //322
    "SKEW",                                              //323
    "ZTEST",                                             //324
    "LARGE",                                             //325
    "SMALL",                                             //326
    "QUARTILE",                                          //327
    "PERCENTILE",                                        //328
    "PERCENTRANK",                                       //329
    "MODE",                                              //330
    "TRIMMEAN",                                          //331
    "TINV",                                              //332
    NULL,
    "MOVIE.COMMAND",                                     //334
    "GET.MOVIE",                                         //335
    "CONCATENATE",                                       //336
    "POWER",                                             //337
    "PIVOT.ADD.DATA",                                    //338
    "GET.PIVOT.TABLE",                                   //339
    "GET.PIVOT.FIELD",                                   //340
    "GET.PIVOT.ITEM",                                    //341
    "RADIANS",                                           //342
    "DEGREES",                                           //343
    "SUBTOTAL",                                          //344
    "SUMIF",                                             //345
    "COUNTIF",                                           //346
    "COUNTBLANK",                                        //347
    "SCENARIO.GET",                                      //348
    "OPTIONS.LISTS.GET",                                 //349
    "ISPMT",                                             //350
    "DATEDIF",                                           //351
    "DATESTRING",                                        //352
    "NUMBERSTRING",                                      //353
    "ROMAN",                                             //354
    "OPEN.DIALOG",                                       //355
    "SAVE.DIALOG",                                       //356
    "VIEW.GET",                                          //357
    "GETPIVOTDATA",                                      //358
    "HYPERLINK",                                         //359
    "PHONETIC",                                          //360
    "AVERAGEA",                                          //361
    "MAXA",                                              //362
    "MINA",                                              //363
    "STDEVPA",                                           //364
    "VARPA",                                             //365
    "STDEVA",                                            //366
    "VARA",                                              //367
    "BAHTTEXT",                                          //368
    "THAIDAYOFWEEK",                                     //369
    "THAIDIGIT",                                         //370
    "THAIMONTHOFYEAR",                                   //371
    "THAINUMSOUND",                                      //372
    "THAINUMSTRING",                                     //373
    "THAISTRINGLENGTH",                                  //374
    "ISTHAIDIGIT",                                       //375
    "ROUNDBAHTDOWN",                                     //376
    "ROUNDBAHTUP",                                       //377
    "THAIYEAR",                                          //378
    "RTD",                                               //379
};
// clang-format on

// clang-format off
char *EXTENDED_FUNCTIONS[] = {
    "BEEP",                                              //32768
    "OPEN",                                              //32769
    "OPEN.LINKS",                                        //32770
    "CLOSE.ALL",                                         //32771
    "SAVE",                                              //32772
    "SAVE.AS",                                           //32773
    "FILE.DELETE",                                       //32774
    "PAGE.SETUP",                                        //32775
    "PRINT",                                             //32776
    "PRINTER.SETUP",                                     //32777
    "QUIT",                                              //32778
    "NEW.WINDOW",                                        //32779
    "ARRANGE.ALL",                                       //32780
    "WINDOW.SIZE",                                       //32781
    "WINDOW.MOVE",                                       //32782
    "FULL",                                              //32783
    "CLOSE",                                             //32784
    "RUN",                                               //32785
    NULL,
    NULL,
    NULL,
    NULL,
    "SET.PRINT.AREA",                                    //32790
    "SET.PRINT.TITLES",                                  //32791
    "SET.PAGE.BREAK",                                    //32792
    "REMOVE.PAGE.BREAK",                                 //32793
    "FONT",                                              //32794
    "DISPLAY",                                           //32795
    "PROTECT.DOCUMENT",                                  //32796
    "PRECISION",                                         //32797
    "A1.R1C1",                                           //32798
    "CALCULATE.NOW",                                     //32799
    "CALCULATION",                                       //32800
    NULL,
    "DATA.FIND",                                         //32802
    "EXTRACT",                                           //32803
    "DATA.DELETE",                                       //32804
    "SET.DATABASE",                                      //32805
    "SET.CRITERIA",                                      //32806
    "SORT",                                              //32807
    "DATA.SERIES",                                       //32808
    "TABLE",                                             //32809
    "FORMAT.NUMBER",                                     //32810
    "ALIGNMENT",                                         //32811
    "STYLE",                                             //32812
    "BORDER",                                            //32813
    "CELL.PROTECTION",                                   //32814
    "COLUMN.WIDTH",                                      //32815
    "UNDO",                                              //32816
    "CUT",                                               //32817
    "COPY",                                              //32818
    "PASTE",                                             //32819
    "CLEAR",                                             //32820
    "PASTE.SPECIAL",                                     //32821
    "EDIT.DELETE",                                       //32822
    "INSERT",                                            //32823
    "FILL.RIGHT",                                        //32824
    "FILL.DOWN",                                         //32825
    NULL,
    NULL,
    NULL,
    "DEFINE.NAME",                                       //32829
    "CREATE.NAMES",                                      //32830
    "FORMULA.GOTO",                                      //32831
    "FORMULA.FIND",                                      //32832
    "SELECT.LAST.CELL",                                  //32833
    "SHOW.ACTIVE.CELL",                                  //32834
    "GALLERY.AREA",                                      //32835
    "GALLERY.BAR",                                       //32836
    "GALLERY.COLUMN",                                    //32837
    "GALLERY.LINE",                                      //32838
    "GALLERY.PIE",                                       //32839
    "GALLERY.SCATTER",                                   //32840
    "COMBINATION",                                       //32841
    "PREFERRED",                                         //32842
    "ADD.OVERLAY",                                       //32843
    "GRIDLINES",                                         //32844
    "SET.PREFERRED",                                     //32845
    "AXES",                                              //32846
    "LEGEND",                                            //32847
    "ATTACH.TEXT",                                       //32848
    "ADD.ARROW",                                         //32849
    "SELECT.CHART",                                      //32850
    "SELECT.PLOT.AREA",                                  //32851
    "PATTERNS",                                          //32852
    "MAIN.CHART",                                        //32853
    "OVERLAY",                                           //32854
    "SCALE",                                             //32855
    "FORMAT.LEGEND",                                     //32856
    "FORMAT.TEXT",                                       //32857
    "EDIT.REPEAT",                                       //32858
    "PARSE",                                             //32859
    "JUSTIFY",                                           //32860
    "HIDE",                                              //32861
    "UNHIDE",                                            //32862
    "WORKSPACE",                                         //32863
    "FORMULA",                                           //32864
    "FORMULA.FILL",                                      //32865
    "FORMULA.ARRAY",                                     //32866
    "DATA.FIND.NEXT",                                    //32867
    "DATA.FIND.PREV",                                    //32868
    "FORMULA.FIND.NEXT",                                 //32869
    "FORMULA.FIND.PREV",                                 //32870
    "ACTIVATE",                                          //32871
    "ACTIVATE.NEXT",                                     //32872
    "ACTIVATE.PREV",                                     //32873
    "UNLOCKED.NEXT",                                     //32874
    "UNLOCKED.PREV",                                     //32875
    "COPY.PICTURE",                                      //32876
    "SELECT",                                            //32877
    "DELETE.NAME",                                       //32878
    "DELETE.FORMAT",                                     //32879
    "VLINE",                                             //32880
    "HLINE",                                             //32881
    "VPAGE",                                             //32882
    "HPAGE",                                             //32883
    "VSCROLL",                                           //32884
    "HSCROLL",                                           //32885
    "ALERT",                                             //32886
    "NEW",                                               //32887
    "CANCEL.COPY",                                       //32888
    "SHOW.CLIPBOARD",                                    //32889
    "MESSAGE",                                           //32890
    NULL,
    "PASTE.LINK",                                        //32892
    "APP.ACTIVATE",                                      //32893
    "DELETE.ARROW",                                      //32894
    "ROW.HEIGHT",                                        //32895
    "FORMAT.MOVE",                                       //32896
    "FORMAT.SIZE",                                       //32897
    "FORMULA.REPLACE",                                   //32898
    "SEND.KEYS",                                         //32899
    "SELECT.SPECIAL",                                    //32900
    "APPLY.NAMES",                                       //32901
    "REPLACE.FONT",                                      //32902
    "FREEZE.PANES",                                      //32903
    "SHOW.INFO",                                         //32904
    "SPLIT",                                             //32905
    "ON.WINDOW",                                         //32906
    "ON.DATA",                                           //32907
    "DISABLE.INPUT",                                     //32908
    NULL,
    "OUTLINE",                                           //32910
    "LIST.NAMES",                                        //32911
    "FILE.CLOSE",                                        //32912
    "SAVE.WORKBOOK",                                     //32913
    "DATA.FORM",                                         //32914
    "COPY.CHART",                                        //32915
    "ON.TIME",                                           //32916
    "WAIT",                                              //32917
    "FORMAT.FONT",                                       //32918
    "FILL.UP",                                           //32919
    "FILL.LEFT",                                         //32920
    "DELETE.OVERLAY",                                    //32921
    NULL,
    "SHORT.MENUS",                                       //32923
    NULL,
    NULL,
    NULL,
    "SET.UPDATE.STATUS",                                 //32927
    NULL,
    "COLOR.PALETTE",                                     //32929
    "DELETE.STYLE",                                      //32930
    "WINDOW.RESTORE",                                    //32931
    "WINDOW.MAXIMIZE",                                   //32932
    NULL,
    "CHANGE.LINK",                                       //32934
    "CALCULATE.DOCUMENT",                                //32935
    "ON.KEY",                                            //32936
    "APP.RESTORE",                                       //32937
    "APP.MOVE",                                          //32938
    "APP.SIZE",                                          //32939
    "APP.MINIMIZE",                                      //32940
    "APP.MAXIMIZE",                                      //32941
    "BRING.TO.FRONT",                                    //32942
    "SEND.TO.BACK",                                      //32943
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "MAIN.CHART.TYPE",                                   //32953
    "OVERLAY.CHART.TYPE",                                //32954
    "SELECT.END",                                        //32955
    "OPEN.MAIL",                                         //32956
    "SEND.MAIL",                                         //32957
    "STANDARD.FONT",                                     //32958
    "CONSOLIDATE",                                       //32959
    "SORT.SPECIAL",                                      //32960
    "GALLERY.3D.AREA",                                   //32961
    "GALLERY.3D.COLUMN",                                 //32962
    "GALLERY.3D.LINE",                                   //32963
    "GALLERY.3D.PIE",                                    //32964
    "VIEW.3D",                                           //32965
    "GOAL.SEEK",                                         //32966
    "WORKGROUP",                                         //32967
    "FILL.GROUP",                                        //32968
    "UPDATE.LINK",                                       //32969
    "PROMOTE",                                           //32970
    "DEMOTE",                                            //32971
    "SHOW.DETAIL",                                       //32972
    NULL,
    "UNGROUP",                                           //32974
    "OBJECT.PROPERTIES",                                 //32975
    "SAVE.NEW.OBJECT",                                   //32976
    "SHARE",                                             //32977
    "SHARE.NAME",                                        //32978
    "DUPLICATE",                                         //32979
    "APPLY.STYLE",                                       //32980
    "ASSIGN.TO.OBJECT",                                  //32981
    "OBJECT.PROTECTION",                                 //32982
    "HIDE.OBJECT",                                       //32983
    "SET.EXTRACT",                                       //32984
    "CREATE.PUBLISHER",                                  //32985
    "SUBSCRIBE.TO",                                      //32986
    "ATTRIBUTES",                                        //32987
    "SHOW.TOOLBAR",                                      //32988
    NULL,
    "PRINT.PREVIEW",                                     //32990
    "EDIT.COLOR",                                        //32991
    "SHOW.LEVELS",                                       //32992
    "FORMAT.MAIN",                                       //32993
    "FORMAT.OVERLAY",                                    //32994
    "ON.RECALC",                                         //32995
    "EDIT.SERIES",                                       //32996
    "DEFINE.STYLE",                                      //32997
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "LINE.PRINT",                                        //33008
    NULL,
    NULL,
    "ENTER.DATA",                                        //33011
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "GALLERY.RADAR",                                     //33017
    "MERGE.STYLES",                                      //33018
    "EDITION.OPTIONS",                                   //33019
    "PASTE.PICTURE",                                     //33020
    "PASTE.PICTURE.LINK",                                //33021
    "SPELLING",                                          //33022
    NULL,
    "ZOOM",                                              //33024
    NULL,
    NULL,
    "INSERT.OBJECT",                                     //33027
    "WINDOW.MINIMIZE",                                   //33028
    NULL,
    NULL,
    NULL,
    NULL,
    "SOUND.NOTE",                                        //33033
    "SOUND.PLAY",                                        //33034
    "FORMAT.SHAPE",                                      //33035
    "EXTEND.POLYGON",                                    //33036
    "FORMAT.AUTO",                                       //33037
    NULL,
    NULL,
    "GALLERY.3D.BAR",                                    //33040
    "GALLERY.3D.SURFACE",                                //33041
    "FILL.AUTO",                                         //33042
    NULL,
    "CUSTOMIZE.TOOLBAR",                                 //33044
    "ADD.TOOL",                                          //33045
    "EDIT.OBJECT",                                       //33046
    "ON.DOUBLECLICK",                                    //33047
    "ON.ENTRY",                                          //33048
    "WORKBOOK.ADD",                                      //33049
    "WORKBOOK.MOVE",                                     //33050
    "WORKBOOK.COPY",                                     //33051
    "WORKBOOK.OPTIONS",                                  //33052
    "SAVE.WORKSPACE",                                    //33053
    NULL,
    NULL,
    "CHART.WIZARD",                                      //33056
    "DELETE.TOOL",                                       //33057
    "MOVE.TOOL",                                         //33058
    "WORKBOOK.SELECT",                                   //33059
    "WORKBOOK.ACTIVATE",                                 //33060
    "ASSIGN.TO.TOOL",                                    //33061
    NULL,
    "COPY.TOOL",                                         //33063
    "RESET.TOOL",                                        //33064
    "CONSTRAIN.NUMERIC",                                 //33065
    "PASTE.TOOL",                                        //33066
    NULL,
    NULL,
    NULL,
    "WORKBOOK.NEW",                                      //33070
    NULL,
    NULL,
    "SCENARIO.CELLS",                                    //33073
    "SCENARIO.DELETE",                                   //33074
    "SCENARIO.ADD",                                      //33075
    "SCENARIO.EDIT",                                     //33076
    "SCENARIO.SHOW",                                     //33077
    "SCENARIO.SHOW.NEXT",                                //33078
    "SCENARIO.SUMMARY",                                  //33079
    "PIVOT.TABLE.WIZARD",                                //33080
    "PIVOT.FIELD.PROPERTIES",                            //33081
    "PIVOT.FIELD",                                       //33082
    "PIVOT.ITEM",                                        //33083
    "PIVOT.ADD.FIELDS",                                  //33084
    NULL,
    "OPTIONS.CALCULATION",                               //33086
    "OPTIONS.EDIT",                                      //33087
    "OPTIONS.VIEW",                                      //33088
    "ADDIN.MANAGER",                                     //33089
    "MENU.EDITOR",                                       //33090
    "ATTACH.TOOLBARS",                                   //33091
    "VBAActivate",                                       //33092
    "OPTIONS.CHART",                                     //33093
    NULL,
    NULL,
    "VBA.INSERT.FILE",                                   //33096
    NULL,
    "VBA.PROCEDURE.DEFINITION",                          //33098
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "ROUTING.SLIP",                                      //33104
    NULL,
    "ROUTE.DOCUMENT",                                    //33106
    "MAIL.LOGON",                                        //33107
    NULL,
    NULL,
    "INSERT.PICTURE",                                    //33110
    "EDIT.TOOL",                                         //33111
    "GALLERY.DOUGHNUT",                                  //33112
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "CHART.TREND",                                       //33118
    NULL,
    "PIVOT.ITEM.PROPERTIES",                             //33120
    NULL,
    "WORKBOOK.INSERT",                                   //33122
    "OPTIONS.TRANSITION",                                //33123
    "OPTIONS.GENERAL",                                   //33124
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "FILTER.ADVANCED",                                   //33138
    NULL,
    NULL,
    "MAIL.ADD.MAILER",                                   //33141
    "MAIL.DELETE.MAILER",                                //33142
    "MAIL.REPLY",                                        //33143
    "MAIL.REPLY.ALL",                                    //33144
    "MAIL.FORWARD",                                      //33145
    "MAIL.NEXT.LETTER",                                  //33146
    "DATA.LABEL",                                        //33147
    "INSERT.TITLE",                                      //33148
    "FONT.PROPERTIES",                                   //33149
    "MACRO.OPTIONS",                                     //33150
    "WORKBOOK.HIDE",                                     //33151
    "WORKBOOK.UNHIDE",                                   //33152
    "WORKBOOK.DELETE",                                   //33153
    "WORKBOOK.NAME",                                     //33154
    NULL,
    "GALLERY.CUSTOM",                                    //33156
    NULL,
    "ADD.CHART.AUTOFORMAT",                              //33158
    "DELETE.CHART.AUTOFORMAT",                           //33159
    "CHART.ADD.DATA",                                    //33160
    "AUTO.OUTLINE",                                      //33161
    "TAB.ORDER",                                         //33162
    "SHOW.DIALOG",                                       //33163
    "SELECT.ALL",                                        //33164
    "UNGROUP.SHEETS",                                    //33165
    "SUBTOTAL.CREATE",                                   //33166
    "SUBTOTAL.REMOVE",                                   //33167
    "RENAME.OBJECT",                                     //33168
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "WORKBOOK.SCROLL",                                   //33180
    "WORKBOOK.NEXT",                                     //33181
    "WORKBOOK.PREV",                                     //33182
    "WORKBOOK.TAB.SPLIT",                                //33183
    "FULL.SCREEN",                                       //33184
    "WORKBOOK.PROTECT",                                  //33185
    NULL,
    NULL,
    "SCROLLBAR.PROPERTIES",                              //33188
    "PIVOT.SHOW.PAGES",                                  //33189
    "TEXT.TO.COLUMNS",                                   //33190
    "FORMAT.CHARTTYPE",                                  //33191
    "LINK.FORMAT",                                       //33192
    "TRACER.DISPLAY",                                    //33193
    NULL,
    NULL,
    NULL,
    NULL,
    "TRACER.NAVIGATE",                                   //33198
    "TRACER.CLEAR",                                      //33199
    "TRACER.ERROR",                                      //33200
    "PIVOT.FIELD.GROUP",                                 //33201
    "PIVOT.FIELD.UNGROUP",                               //33202
    "CHECKBOX.PROPERTIES",                               //33203
    "LABEL.PROPERTIES",                                  //33204
    "LISTBOX.PROPERTIES",                                //33205
    "EDITBOX.PROPERTIES",                                //33206
    "PIVOT.REFRESH",                                     //33207
    "LINK.COMBO",                                        //33208
    "OPEN.TEXT",                                         //33209
    "HIDE.DIALOG",                                       //33210
    "SET.DIALOG.FOCUS",                                  //33211
    "ENABLE.OBJECT",                                     //33212
    "PUSHBUTTON.PROPERTIES",                             //33213
    "SET.DIALOG.DEFAULT",                                //33214
    "FILTER",                                            //33215
    "FILTER.SHOW.ALL",                                   //33216
    "CLEAR.OUTLINE",                                     //33217
    "FUNCTION.WIZARD",                                   //33218
    "ADD.LIST.ITEM",                                     //33219
    "SET.LIST.ITEM",                                     //33220
    "REMOVE.LIST.ITEM",                                  //33221
    "SELECT.LIST.ITEM",                                  //33222
    "SET.CONTROL.VALUE",                                 //33223
    "SAVE.COPY.AS",                                      //33224
    NULL,
    "OPTIONS.LISTS.ADD",                                 //33226
    "OPTIONS.LISTS.DELETE",                              //33227
    "SERIES.AXES",                                       //33228
    "SERIES.X",                                          //33229
    "SERIES.Y",                                          //33230
    "ERRORBAR.X",                                        //33231
    "ERRORBAR.Y",                                        //33232
    "FORMAT.CHART",                                      //33233
    "SERIES.ORDER",                                      //33234
    "MAIL.LOGOFF",                                       //33235
    "CLEAR.ROUTING.SLIP",                                //33236
    "APP.ACTIVATE.MICROSOFT",                            //33237
    "MAIL.EDIT.MAILER",                                  //33238
    "ON.SHEET",                                          //33239
    "STANDARD.WIDTH",                                    //33240
    "SCENARIO.MERGE",                                    //33241
    "SUMMARY.INFO",                                      //33242
    "FIND.FILE",                                         //33243
    "ACTIVE.CELL.FONT",                                  //33244
    "ENABLE.TIPWIZARD",                                  //33245
    "VBA.MAKE.ADDIN",                                    //33246
    NULL,
    "INSERTDATATABLE",                                   //33248
    "WORKGROUP.OPTIONS",                                 //33249
    "MAIL.SEND.MAILER",                                  //33250
    NULL,
    NULL,
    "AUTOCORRECT",                                       //33253
    NULL,
    NULL,
    NULL,
    "POST.DOCUMENT",                                     //33257
    NULL,
    "PICKLIST",                                          //33259
    NULL,
    "VIEW.SHOW",                                         //33261
    "VIEW.DEFINE",                                       //33262
    "VIEW.DELETE",                                       //33263
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "SHEET.BACKGROUND",                                  //33277
    "INSERT.MAP.OBJECT",                                 //33278
    "OPTIONS.MENONO",                                    //33279
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "MSOCHECKS",                                         //33285
    "NORMAL",                                            //33286
    "LAYOUT",                                            //33287
    "RM.PRINT.AREA",                                     //33288
    "CLEAR.PRINT.AREA",                                  //33289
    "ADD.PRINT.AREA",                                    //33290
    "MOVE.BRK",                                          //33291
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "HIDECURR.NOTE",                                     //33313
    "HIDEALL.NOTES",                                     //33314
    "DELETE.NOTE",                                       //33315
    "TRAVERSE.NOTES",                                    //33316
    "ACTIVATE.NOTES",                                    //33317
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "PROTECT.REVISIONS",                                 //33388
    "UNPROTECT.REVISIONS",                               //33389
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "OPTIONS.ME",                                        //33415
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "WEB.PUBLISH",                                       //33421
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "NEWWEBQUERY",                                       //33435
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "PIVOT.TABLE.CHART",                                 //33441
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "OPTIONS.SAVE",                                      //33521
    NULL,
    "OPTIONS.SPELL",                                     //33523
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "HIDEALL.INKANNOTS",                                 //33576
};

char *TOKENS[] = {
    NULL,
    "ptgExp",                                            //1
    "ptgTbl",                                            //2
    "ptgAdd",                                            //3
    "ptgSub",                                            //4
    "ptgMul",                                            //5
    "ptgDiv",                                            //6
    "ptgPower",                                          //7
    "ptgConcat",                                         //8
    "ptgLT",                                             //9
    "ptgLE",                                             //10
    "ptgEQ",                                             //11
    "ptgGE",                                             //12
    "ptgGT",                                             //13
    "ptgNE",                                             //14
    "ptgIsect",                                          //15
    "ptgUnion",                                          //16
    "ptgRange",                                          //17
    "ptgUplus",                                          //18
    "ptgUminus",                                         //19
    "ptgPercent",                                        //20
    "ptgParen",                                          //21
    "ptgMissArg",                                        //22
    "ptgStr",                                            //23
    NULL,
    "ptgAttr",                                           //25
    "ptgSheet",                                          //26
    "ptgEndSheet",                                       //27
    "ptgErr",                                            //28
    "ptgBool",                                           //29
    "ptgInt",                                            //30
    "ptgNum",                                            //31
    "ptgArray",                                          //32
    "ptgFunc",                                           //33
    "ptgFuncVar",                                        //34
    "ptgName",                                           //35
    "ptgRef",                                            //36
    "ptgArea",                                           //37
    "ptgMemArea",                                        //38
    "ptgMemErr",                                         //39
    "ptgMemNoMem",                                       //40
    "ptgMemFunc",                                        //41
    "ptgRefErr",                                         //42
    "ptgAreaErr",                                        //43
    "ptgRefN",                                           //44
    "ptgAreaN",                                          //45
    "ptgMemAreaN",                                       //46
    "ptgMemNoMemN",                                      //47
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "ptgNameX",                                          //57
    "ptgRef3d",                                          //58
    "ptgArea3d",                                         //59
    "ptgRefErr3d",                                       //60
    "ptgAreaErr3d",                                      //61
    NULL,
    NULL,
    "ptgArrayV",                                         //64
    "ptgFuncV",                                          //65
    "ptgFuncVarV",                                       //66
    "ptgNameV",                                          //67
    "ptgRefV",                                           //68
    "ptgAreaV",                                          //69
    "ptgMemAreaV",                                       //70
    "ptgMemErrV",                                        //71
    "ptgMemNoMemV",                                      //72
    "ptgMemFuncV",                                       //73
    "ptgRefErrV",                                        //74
    "ptgAreaErrV",                                       //75
    "ptgRefNV",                                          //76
    "ptgAreaNV",                                         //77
    "ptgMemAreaNV",                                      //78
    "ptgMemNoMemNV",                                     //79
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "ptgFuncCEV",                                        //88
    "ptgNameXV",                                         //89
    "ptgRef3dV",                                         //90
    "ptgArea3dV",                                        //91
    "ptgRefErr3dV",                                      //92
    "ptgAreaErr3dV",                                     //93
    NULL,
    NULL,
    "ptgArrayA",                                         //96
    "ptgFuncA",                                          //97
    "ptgFuncVarA",                                       //98
    "ptgNameA",                                          //99
    "ptgRefA",                                           //100
    "ptgAreaA",                                          //101
    "ptgMemAreaA",                                       //102
    "ptgMemErrA",                                        //103
    "ptgMemNoMemA",                                      //104
    "ptgMemFuncA",                                       //105
    "ptgRefErrA",                                        //106
    "ptgAreaErrA",                                       //107
    "ptgRefNA",                                          //108
    "ptgAreaNA",                                         //109
    "ptgMemAreaNA",                                      //110
    "ptgMemNoMemNA",                                     //111
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    "ptgFuncCEA",                                        //120
    "ptgNameXA",                                         //121
    "ptgRef3dA",                                         //122
    "ptgArea3dA",                                        //123
    "ptgRefErr3dA",                                      //124
    "ptgAreaErr3dA",                                     //125
};
// clang-format on

typedef enum ptg_expr {
    ptgExp        = 0x01,
    ptgTbl        = 0x02,
    ptgAdd        = 0x03,
    ptgSub        = 0x04,
    ptgMul        = 0x05,
    ptgDiv        = 0x06,
    ptgPower      = 0x07,
    ptgConcat     = 0x08,
    ptgLt         = 0x09,
    ptgLe         = 0x0A,
    ptgEq         = 0x0B,
    ptgGe         = 0x0C,
    ptgGt         = 0x0D,
    ptgNe         = 0x0E,
    ptgIsect      = 0x0F,
    ptgUnion      = 0x10,
    ptgRange      = 0x11,
    ptgUplus      = 0x12,
    ptgUminus     = 0x13,
    ptgPercent    = 0x14,
    ptgParen      = 0x15,
    ptgMissArg    = 0x16,
    ptgStr        = 0x17,
    ptgEscape1    = 0x18,
    ptgAttr       = 0x19,
    ptgErr        = 0x1C,
    ptgBool       = 0x1D,
    ptgInt        = 0x1E,
    ptgNum        = 0x1F,
    ptgArray      = 0x20,
    ptgFunc       = 0x21,
    ptgFuncVar    = 0x22,
    ptgName       = 0x23,
    ptgRef        = 0x24,
    ptgArea       = 0x25,
    ptgMemArea    = 0x26,
    ptgMemErr     = 0x27,
    ptgMemNoMem   = 0x28,
    ptgMemFunc    = 0x29,
    ptgRefErr     = 0x2A,
    ptgAreaErr    = 0x2B,
    ptgRefN       = 0x2C,
    ptgAreaN      = 0x2D,
    ptgNameX      = 0x39,
    ptgRef3d      = 0x3A,
    ptgArea3d     = 0x3B,
    ptgRefErr3d   = 0x3C,
    ptgAreaErr3d  = 0x3D,
    ptgArrayV     = 0x40,
    ptgFuncV      = 0x41,
    ptgFuncVarV   = 0x42,
    ptgNameV      = 0x43,
    ptgRefV       = 0x44,
    ptgAreaV      = 0x45,
    ptgMemAreaV   = 0x46,
    ptgMemErrV    = 0x47,
    ptgMemNoMemV  = 0x48,
    ptgMemFuncV   = 0x49,
    ptgRefErrV    = 0x4A,
    ptgAreaErrV   = 0x4B,
    ptgRefNV      = 0x4C,
    ptgAreaNV     = 0x4D,
    ptgNameXV     = 0x59,
    ptgRef3dV     = 0x5A,
    ptgArea3dV    = 0x5B,
    ptgRefErr3dV  = 0x5C,
    ptgAreaErr3dV = 0x5D,
    ptgArrayA     = 0x60,
    ptgFuncA      = 0x61,
    ptgFuncVarA   = 0x62,
    ptgNameA      = 0x63,
    ptgRefA       = 0x64,
    ptgAreaA      = 0x65,
    ptgMemAreaA   = 0x66,
    ptgMemErrA    = 0x67,
    ptgMemNoMemA  = 0x68,
    ptgMemFuncA   = 0x69,
    ptgRefErrA    = 0x6A,
    ptgAreaErrA   = 0x6B,
    ptgRefNA      = 0x6C,
    ptgAreaNA     = 0x6D,
    ptgNameXA     = 0x79,
    ptgRef3dA     = 0x7A,
    ptgArea3dA    = 0x7B,
    ptgRefErr3dA  = 0x7C,
    ptgAreaErr3dA = 0x7D,

} ptg_expr;

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

/**
 * @brief The OfficeArtRecordHeader fined on page 27 of the MSO-ODRAW specification:
 *   https://interoperability.blob.core.windows.net/files/MS-ODRAW/%5bMS-ODRAW%5d.pdf
 *
 * We'll use this to extract images found in office documents.
 */
struct OfficeArtRecordHeader_PackedLittleEndian {
    uint16_t recVerAndInstance; // 4 bytes for recVer, 12 bytes for recInstance
    uint16_t recType;
    uint32_t recLen;
} __attribute__((packed));

/**
 * @brief The OfficeArtFBSE structure following its record header.
 * See section 2.2.32 OfficeArtFBSE in:
 *   https://interoperability.blob.core.windows.net/files/MS-ODRAW/%5bMS-ODRAW%5d.pdf
 *
 * Does not include the variable size nameData
 */
struct OfficeArtFBSE_PackedLittleEndian {
    uint8_t btWin32; // 1-byte enum containing a mso_blip_type value
    uint8_t btMacOS; // 1-byte enum containing a mso_blip_type value
    unsigned char rgbUid[16];
    uint16_t tag;
    uint32_t size;    // size of the Blip stream
    uint32_t cRef;    // number of references to the Blip
    uint32_t foDelay; // An MSOFOstructure, as defined in section 2.1.4, must be 0x00000000
    uint8_t unused1;  // unused
    uint8_t cbName;   // length of the name field, in bytes.
    uint8_t unused2;  // unused
    uint8_t unused3;  // unused
} __attribute__((packed));

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

struct OfficeArtRecordHeader_Unpacked {
    uint16_t recVer;
    uint16_t recInstance;
    uint16_t recType;
    uint32_t recLen;
} __attribute__((packed));

typedef enum {
    msoblip_ERROR    = 0x00, // Error reading the file.
    msoblip_UNKNOWN  = 0x01, // Unknown BLIPtype.
    msoblip_EMF      = 0x02, // EMF.
    msoblip_WMF      = 0x03, // WMF.
    msoblip_PICT     = 0x04, // Macintosh PICT.
    msoblip_JPEG     = 0x05, // JPEG.
    msoblip_PNG      = 0x06, // PNG.
    msoblip_DIB      = 0x07, // DIB
    msoblip_TIFF     = 0x11, // TIFF
    msoblip_CMYKJPEG = 0x12, // JPEG in the YCCK or CMYK color space.
} mso_blip_type;

/**
 * @brief Read the office art record header information from a buffer
 *
 * @param data                      data buffer starting with the record header
 * @param data_len                  length of the buffer
 * @param[in,out] unpacked_header   fill this
 * @return cl_error_t               CL_SUCCESS if successful, else some error code.
 */
static cl_error_t
read_office_art_record_header(const unsigned char *data, size_t data_len, struct OfficeArtRecordHeader_Unpacked *unpacked_header)
{
    cl_error_t status = CL_EARG;
    uint16_t recVerAndInstance;
    struct OfficeArtRecordHeader_PackedLittleEndian *rawHeader;

    if ((NULL == data) ||
        (sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) > data_len) ||
        (NULL == unpacked_header)) {
        // invalid args
        goto done;
    }

    rawHeader = (struct OfficeArtRecordHeader_PackedLittleEndian *)data;

    recVerAndInstance = le16_to_host(rawHeader->recVerAndInstance);

    unpacked_header->recVer      = recVerAndInstance & 0x000F;
    unpacked_header->recInstance = (recVerAndInstance & 0xFFF0) >> 4;
    unpacked_header->recType     = le16_to_host(rawHeader->recType);
    unpacked_header->recLen      = le32_to_host(rawHeader->recLen);

    cli_dbgmsg("read_office_art_record_header: office art record:\n");
    cli_dbgmsg("read_office_art_record_header:   recVer       0x%x\n", unpacked_header->recVer);
    cli_dbgmsg("read_office_art_record_header:   recInstance  0x%x\n", unpacked_header->recInstance);
    cli_dbgmsg("read_office_art_record_header:   recType      0x%x\n", unpacked_header->recType);
    cli_dbgmsg("read_office_art_record_header:   recLen       %u\n", unpacked_header->recLen);

    status = CL_SUCCESS;

done:
    return status;
}

static const char *get_function_name(unsigned index)
{
    if (index < sizeof(FUNCTIONS) / sizeof(FUNCTIONS[0])) {
        return FUNCTIONS[index];
    } else if (index >= 0x8000 &&
               (index - 0x8000 < sizeof(EXTENDED_FUNCTIONS) / sizeof(EXTENDED_FUNCTIONS[0]))) {
        return EXTENDED_FUNCTIONS[index - 0x8000];
    } else {
        return NULL;
    }
}

static cl_error_t parse_formula(FILE *out_file, char data[], unsigned data_size)
{
    cl_error_t status = CL_EFORMAT;
    unsigned data_pos = 0;
    int len;
    size_t size_written;

    while (data_pos < data_size) {
        ptg_expr ptg = data[data_pos] & 0x7f;

        if (((uint8_t)data[data_pos]) < sizeof(TOKENS) / sizeof(TOKENS[0])) {
            len = fprintf(out_file, " %s", TOKENS[ptg]);
            if (len < 0) {
                cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting token name\n");
                goto done;
            }
        }

        switch (ptg) {
            case ptgAdd:
            case ptgSub:
            case ptgMul:
            case ptgDiv:
            case ptgConcat:
            case ptgLt:
            case ptgLe:
            case ptgEq:
            case ptgGe:
            case ptgGt:
            case ptgNe:
            case ptgMissArg:
            case ptgRange:
                data_pos += 1;
                break;
            case ptgStr:
                if (data_pos + 2 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgStr record\n");
                    goto done;
                }

                if (data[data_pos + 2] == 1 && data_pos + 2 + 2 * data[data_pos + 1] <= data_size) {
                    char *utf8       = NULL;
                    size_t utf8_size = 0;
                    // TODO: Is this really times two here? Or is the string length in bytes?
                    size_t str_len = data[data_pos + 1] * 2;
                    if (str_len > data_size - data_pos) {
                        str_len = data_size - data_pos;
                    }
                    if (CL_SUCCESS == cli_codepage_to_utf8(&data[data_pos + 3], str_len, CODEPAGE_UTF16_LE, &utf8, &utf8_size)) {
                        if (0 < utf8_size) {
                            size_written = fwrite(utf8, 1, utf8_size, out_file);
                            free(utf8);
                            if (size_written < utf8_size) {
                                cli_dbgmsg("[cli_extract_xlm_macros_and_images] Error writing STRING record message with UTF16LE content\n");
                                goto done;
                            }
                        }
                    } else {
                        cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Failed to decode UTF16LE string in formula\n");
                        len = fprintf(out_file, "<Failed to decode UTF16LE string>");
                        if (len < 0) {
                            cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgStr message with UTF16LE content\n");
                            goto done;
                        }
                    }
                    data_pos += 3 + str_len;
                } else if (data[data_pos + 2] == 0 && data_pos + 2 + data[data_pos + 1] <= data_size) {
                    unsigned str_len = data[data_pos + 1];
                    if (str_len > data_size - data_pos) {
                        str_len = data_size - data_pos;
                    }
                    if (0 < str_len) {
                        size_written = fwrite(&data[data_pos], 1, str_len, out_file);
                        if (size_written < str_len) {
                            cli_dbgmsg("[cli_extract_xlm_macros_and_images] Error writing STRING record message with UTF16LE content\n");
                            goto done;
                        }
                    }
                    data_pos += 3 + str_len;
                } else {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images] Invalid or truncated string record!\n");
                    goto done;
                }
                break;
            case ptgAttr:
                if (data_pos + 1 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgAttr record\n");
                    goto done;
                }

                if (data[data_pos + 1] & 0x40) {
                    uint16_t coffset;

                    if (data_pos + 3 >= data_size) {
                        cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgAttrChoose record\n");
                        goto done;
                    }

                    coffset = data[data_pos + 2] | (data[data_pos + 3] << 8);

                    len = fprintf(out_file, " CHOOSE (%u)", (unsigned)(coffset + 1));
                    if (len < 0) {
                        cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgAttr message\n");
                        goto done;
                    }

                    data_pos += 4 + 2 * (coffset + 1);
                } else {
                    data_pos += 4;
                }
                break;
            case ptgBool:
                if (data_pos + 1 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgBool record\n");
                    goto done;
                }

                len = fprintf(out_file, " %s", data[data_pos + 1] ? "TRUE" : "FALSE");
                if (len < 0) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgBool message\n");
                    goto done;
                }

                data_pos += 2;
                break;
            case ptgInt:
                if (data_pos + 2 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgInt record\n");
                    goto done;
                }

                len = fprintf(out_file, " %d", data[data_pos + 1] | (data[data_pos + 2] << 8));
                if (len < 0) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgInt message\n");
                    goto done;
                }

                data_pos += 3;
                break;
            case ptgFunc:
            case ptgFuncV:
            case ptgFuncA: {
                if (data_pos + 2 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgFunc record\n");
                    goto done;
                }

                uint16_t func_id      = data[data_pos + 1] | (data[data_pos + 2] << 8);
                const char *func_name = get_function_name(func_id);

                len = fprintf(out_file, " %s (0x%04x)", func_name == NULL ? "<unknown function>" : func_name, func_id);
                if (len < 0) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgFunc message\n");
                    goto done;
                }

                data_pos += 3;
                break;
            }
            case ptgFuncVar:
            case ptgFuncVarV:
            case ptgFuncVarA: {
                if (data_pos + 3 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgFuncVar record\n");
                    goto done;
                }

                uint16_t func_id      = data[data_pos + 2] | (data[data_pos + 3] << 8);
                const char *func_name = get_function_name(func_id);

                len = fprintf(
                    out_file,
                    " args %u func %s (0x%04x)",
                    (unsigned)data[data_pos + 1],
                    func_name == NULL ? "<unknown function>" : func_name,
                    func_id);
                if (len < 0) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgFuncVar message\n");
                    goto done;
                }

                data_pos += 4;
                if (func_id == 0x806d) {
                    data_pos += 9;
                }
                break;
            }
            case ptgName: {
                if (data_pos + 4 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgName record\n");
                    goto done;
                }

                uint32_t val = data[data_pos + 1] | (data[data_pos + 2] << 8) | (data[data_pos + 3] << 16) | (data[data_pos + 4] << 24);

                len = fprintf(out_file, " 0x%08x", val);
                if (len < 0) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgName message\n");
                    goto done;
                }

                data_pos += 5;
                break;
            }
            case ptgNum: {
                if (data_pos + 8 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgNum record\n");
                    goto done;
                }

                double val = *(double *)&data[data_pos + 1];

                len = fprintf(out_file, " %f", val);
                if (len < 0) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgNum message\n");
                    goto done;
                }

                data_pos += 9;
                break;
            }
            case ptgMemArea: {
                if (data_pos + 6 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgMemArea record\n");
                    goto done;
                }

                len = fprintf(out_file, " REFERENCE-EXPRESSION");
                if (len < 0) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgMemArea message\n");
                    goto done;
                }

                data_pos += 7;
                break;
            }
            case ptgExp: {
                if (data_pos + 4 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgExp record\n");
                    goto done;
                }
                uint16_t row    = data[data_pos + 1] | (data[data_pos + 2] << 8);
                uint16_t column = data[data_pos + 3] | (data[data_pos + 4] << 8);

                len = fprintf(out_file, " R%uC%u", (unsigned)(row + 1), (unsigned)(column + 1));
                if (len < 0) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgExp message\n");
                    goto done;
                }

                data_pos += 5;
                break;
            }
            case ptgRef:
            case ptgRefV: {
                if (data_pos + 4 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgRef record\n");
                    goto done;
                }

                uint16_t row    = data[data_pos + 1] | (data[data_pos + 2] << 8);
                uint16_t column = data[data_pos + 3] | (data[data_pos + 4] << 8);

                len = fprintf(
                    out_file,
                    " R%s%uC%s%u",
                    (row & (1 << 14)) ? "~" : "",
                    (unsigned)((row & 0x3fff) + ((row & (1 << 14)) ? 0 : 1)),
                    (row & (1 << 15)) ? "~" : "",
                    (unsigned)(column + ((row & (1 << 15)) ? 0 : 1)));
                if (len < 0) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgRef message\n");
                    goto done;
                }
                data_pos += 5;
                break;
            }
            case ptgArea: {
                if (data_pos + 8 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgArea record\n");
                    goto done;
                }

                uint16_t row1    = data[data_pos + 1] | (data[data_pos + 2] << 8);
                uint16_t column1 = data[data_pos + 3] | (data[data_pos + 4] << 8);
                uint16_t row2    = data[data_pos + 5] | (data[data_pos + 6] << 8);
                uint16_t column2 = data[data_pos + 7] | (data[data_pos + 8] << 8);

                len = fprintf(
                    out_file,
                    " R%s%uC%s%u:R%s%uC%s%u",
                    (row1 & (1 << 14)) ? "~" : "",
                    (unsigned)((row1 & 0x3fff) + ((row1 & (1 << 14)) ? 0 : 1)),
                    (row1 & (1 << 15)) ? "~" : "",
                    (unsigned)(column1 + ((row1 & (1 << 15)) ? 0 : 1)),
                    (row2 & (1 << 14)) ? "~" : "",
                    (unsigned)((row2 & 0x3fff) + ((row2 & (1 << 14)) ? 0 : 1)),
                    (row2 & (1 << 15)) ? "~" : "",
                    (unsigned)(column2 + ((row2 & (1 << 15)) ? 0 : 1)));
                if (len < 0) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgArea message\n");
                    goto done;
                }

                data_pos += 9;
                break;
            }
            case ptgRef3d:
            case ptgRef3dV: {
                if (data_pos + 6 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgRef3d record\n");
                    goto done;
                }

                uint16_t row    = data[data_pos + 3] | (data[data_pos + 4] << 8);
                uint16_t column = data[data_pos + 5] | (data[data_pos + 6] << 8);

                len = fprintf(
                    out_file,
                    " R%s%uC%s%u",
                    (row & (1 << 14)) ? "~" : "",
                    (unsigned)((row & 0x3fff) + ((row & (1 << 14)) ? 0 : 1)),
                    (row & (1 << 15)) ? "~" : "",
                    (unsigned)(column + ((row & (1 << 15)) ? 0 : 1)));
                if (len < 0) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgRef3d message\n");
                    goto done;
                }

                data_pos += 7;
                break;
            }
            case ptgNameX: {
                if (data_pos + 6 >= data_size) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Malformed ptgNameX record\n");
                    goto done;
                }

                uint16_t name = data[data_pos + 3] | (data[data_pos + 4] << 8);

                len = fprintf(
                    out_file,
                    " NAMEIDX %u",
                    (unsigned)name);
                if (len < 0) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Error formatting ptgNameX message\n");
                    goto done;
                }

                data_pos += 7;
                break;
            }
            default:
                if (ptg < sizeof(TOKENS) / sizeof(char *)) {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Encountered unexpected ptg token: %s\n", TOKENS[ptg]);
                } else {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images:parse_formula] Encountered unknown ptg token: 0x%02x\n", ptg);
                }
                goto done;
        }
    }

    status = CL_SUCCESS;

done:
    return status;
}

/**
 * @brief Handle each type of Blip record. See section 2.2.23 OfficeArtBlip in:
 * https://interoperability.blob.core.windows.net/files/MS-ODRAW/%5bMS-ODRAW%5d.pdf
 *
 * @param blip_store_container
 * @param blip_store_container_len
 * @param ctx
 * @return cl_error_t
 */
cl_error_t process_blip_record(struct OfficeArtRecordHeader_Unpacked *rh, const unsigned char *index, size_t remaining, cli_ctx *ctx)
{
    cl_error_t status = CL_EARG;
    cl_error_t ret;

    char *extracted_image_filepath = NULL;
    int extracted_image_tempfd     = -1;

    size_t blip_bytes_before_image      = 0; /* the number of bytes between the record header and the image */
    const unsigned char *start_of_image = NULL;
    size_t size_of_image                = 0;
    const char *extracted_image_type    = NULL;

    if (0x0 != rh->recVer) {
        cli_dbgmsg("process_blip_store_container: Invalid recVer for Blip record header: %u\n", rh->recVer);
    }

    switch (rh->recType) {
        case 0xF01A: { /* OfficeArtBlipEMF */
            cli_dbgmsg("process_blip_store_container: Found OfficeArtBlipEMF (Enhanced Metafile Format)\n");
            if (0x3D4 == rh->recInstance) {
                blip_bytes_before_image += 16 + 34; /* 1 16-byte UID + 34-byte metafile header */
            } else if (0x3D5 == rh->recInstance) {
                blip_bytes_before_image += 32 + 34; /* 2 16-byte UIDs + 34-byte metafile header */
            } else {
                cli_dbgmsg("process_blip_store_container: Invalid recInstance for OfficeArtBlipEMF\n");
            }
            extracted_image_type = "EMF";
            break;
        }
        case 0xF01B: { /* OfficeArtBlipWMF */
            cli_dbgmsg("process_blip_store_container: Found OfficeArtBlipWMF (Windows Metafile Format)\n");
            if (0x216 == rh->recInstance) {
                blip_bytes_before_image += 16 + 34; /* 1 16-byte UID + 34-byte metafile header */
            } else if (0x217 == rh->recInstance) {
                blip_bytes_before_image += 32 + 34; /* 2 16-byte UIDs + 34-byte metafile header */
            } else {
                cli_dbgmsg("process_blip_store_container: Invalid recInstance for OfficeArtBlipWMF\n");
            }
            extracted_image_type = "WMF";
            break;
        }
        case 0xF01C: { /* OfficeArtBlipPICT */
            cli_dbgmsg("process_blip_store_container: Found OfficeArtBlipPICT (Macintosh PICT)\n");
            if (0x542 == rh->recInstance) {
                blip_bytes_before_image += 16 + 34; /* 1 16-byte UID + 34-byte metafile header */
            } else if (0x543 == rh->recInstance) {
                blip_bytes_before_image += 32 + 34; /* 2 16-byte UIDs + 34-byte metafile header */
            } else {
                cli_dbgmsg("process_blip_store_container: Invalid recInstance for OfficeArtBlipPICT\n");
            }
            extracted_image_type = "PICT";
            break;
        }
        case 0xF01D:   /* OfficeArtBlipJPEG */
        case 0xF02A: { /* OfficeArtBlipJPEG */
            cli_dbgmsg("process_blip_store_container: Found OfficeArtBlipJPEG\n");
            if (0x46A == rh->recInstance || 0x6E2 == rh->recInstance) {
                blip_bytes_before_image += 16 + 1; /* 1 16-byte UID + 1-byte tag */
            } else if (0x46B == rh->recInstance || 0x6E3 == rh->recInstance) {
                blip_bytes_before_image += 32 + 1; /* 2 16-byte UIDs + 1-byte tag */
            } else {
                cli_dbgmsg("process_blip_store_container: Invalid recInstance for OfficeArtBlipJPEG\n");
            }
            extracted_image_type = "JPEG";
            break;
        }
        case 0xF01E: { /* OfficeArtBlipPNG */
            cli_dbgmsg("process_blip_store_container: Found OfficeArtBlipPNG\n");
            if (0x6E0 == rh->recInstance) {
                blip_bytes_before_image += 16 + 1; /* 1 16-byte UID + 1-byte tag */
            } else if (0x6E1 == rh->recInstance) {
                blip_bytes_before_image += 32 + 1; /* 2 16-byte UIDs + 1-byte tag */
            } else {
                cli_dbgmsg("process_blip_store_container: Invalid recInstance for OfficeArtBlipPNG\n");
            }
            extracted_image_type = "PNG";
            break;
        }
        case 0xF01F: { /* OfficeArtBlipDIB */
            cli_dbgmsg("process_blip_store_container: Found OfficeArtBlipDIB (device independent bitmap)\n");
            if (0x7A8 == rh->recInstance) {
                blip_bytes_before_image += 16 + 1; /* 1 16-byte UID + 1-byte tag */
            } else if (0x7A9 == rh->recInstance) {
                blip_bytes_before_image += 32 + 1; /* 2 16-byte UIDs + 1-byte tag */
            } else {
                cli_dbgmsg("process_blip_store_container: Invalid recInstance for OfficeArtBlipDIB\n");
            }
            extracted_image_type = "DIB";
            break;
        }
        case 0xF029: { /* OfficeArtBlipTIFF */
            cli_dbgmsg("process_blip_store_container: Found OfficeArtBlipTIFF\n");
            if (0x6E4 == rh->recInstance) {
                blip_bytes_before_image += 16 + 1; /* 1 16-byte UID + 1-byte tag */
            } else if (0x6E5 == rh->recInstance) {
                blip_bytes_before_image += 32 + 1; /* 2 16-byte UIDs + 1-byte tag */
            } else {
                cli_dbgmsg("process_blip_store_container: Invalid recInstance for OfficeArtBlipTIFF\n");
            }
            extracted_image_type = "TIFF";
            break;
        }
        default: {
            cli_dbgmsg("Unknown OfficeArtBlip type!\n");
        }
    }

    if (0 == blip_bytes_before_image) {
        cli_dbgmsg("Was not able to identify the Blip type, skipping...\n");

    } else if (remaining < sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) + blip_bytes_before_image) {
        cli_dbgmsg("Not enough remaining bytes in blip array for image data\n");

    } else {
        start_of_image = index + sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) + blip_bytes_before_image;
        size_of_image  = MIN(rh->recLen, remaining - (sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) + blip_bytes_before_image));

        cli_dbgmsg("Scanning extracted image of size %zu\n", size_of_image);

        if (ctx->engine->keeptmp) {
            /* Drop a temp file and scan that */
            if (CL_SUCCESS != (ret = cli_gentempfd_with_prefix(
                                   ctx->this_layer_tmpdir,
                                   extracted_image_type,
                                   &extracted_image_filepath,
                                   &extracted_image_tempfd))) {
                cli_warnmsg("Failed to create temp file for extracted %s file\n", extracted_image_type);
                status = CL_EOPEN;
                goto done;
            }

            if (cli_writen(extracted_image_tempfd, start_of_image, size_of_image) != size_of_image) {
                cli_errmsg("failed to write output file\n");
                status = CL_EWRITE;
                goto done;
            }

            ret = cli_magic_scan_desc_type(extracted_image_tempfd, extracted_image_filepath, ctx, CL_TYPE_ANY,
                                           NULL, LAYER_ATTRIBUTES_NONE);
        } else {
            /* Scan the buffer */
            ret = cli_magic_scan_buff(start_of_image, size_of_image, ctx, NULL, LAYER_ATTRIBUTES_NONE);
        }
        if (CL_SUCCESS != ret) {
            status = ret;
            goto done;
        }
    }

    if (remaining < sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) + rh->recLen) {
        remaining = 0;
    } else {
        remaining -= sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) + rh->recLen;
        index += sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) + rh->recLen;
    }

    status = CL_SUCCESS;

done:
    if (-1 != extracted_image_tempfd) {
        close(extracted_image_tempfd);
    }
    if (NULL != extracted_image_filepath) {
        free(extracted_image_filepath);
    }

    return status;
}

/**
 * @brief Process each Blip Store Container File Block in a Blip Store Container
 *
 * @param blip_store_container
 * @param blip_store_container_len
 * @param ctx
 * @return cl_error_t
 */
cl_error_t process_blip_store_container(const unsigned char *blip_store_container, size_t blip_store_container_len, cli_ctx *ctx)
{
    cl_error_t status = CL_EARG;

    struct OfficeArtRecordHeader_Unpacked rh;
    const unsigned char *index = blip_store_container;
    size_t remaining           = blip_store_container_len;

    while (0 < remaining) {

        if (CL_SUCCESS != read_office_art_record_header(index, remaining, &rh)) {
            /* Failed to get header, abort. */
            cli_dbgmsg("process_blip_store_container: Failed to get header\n");
            goto done;
        }

        if (0x0 != rh.recVer) {
            cli_dbgmsg("process_blip_store_container: Invalid recVer for Blip record header: %u\n", rh.recVer);
        }

        /*
         * Handle each type of Blip Store Container File Block. See section 2.2.22 OfficeArtBStoreContainerFileBlock in:
         * https://interoperability.blob.core.windows.net/files/MS-ODRAW/%5bMS-ODRAW%5d.pdf
         */
        if (0xF007 == rh.recType) {
            /* it's an OfficeArtFBSErecord */
            cli_dbgmsg("process_blip_store_container: Found a File Blip Store Entry (FBSE) record\n");

            if (0x2 != rh.recVer) {
                cli_dbgmsg("process_blip_store_container: Invalid recVer for OfficeArtFBSErecord: 0x%x\n", rh.recVer);
            }

            if (sizeof(struct OfficeArtFBSE_PackedLittleEndian) > remaining - sizeof(struct OfficeArtRecordHeader_PackedLittleEndian)) {
                cli_dbgmsg("process_blip_store_container: Not enough bytes for FSBE record data\n");
            } else {
                struct OfficeArtFBSE_PackedLittleEndian *FBSE_record_data = (struct OfficeArtFBSE_PackedLittleEndian *)(index + sizeof(struct OfficeArtRecordHeader_PackedLittleEndian));

                if (FBSE_record_data->cbName > remaining - sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) - sizeof(struct OfficeArtFBSE_PackedLittleEndian)) {
                    cli_dbgmsg("process_blip_store_container: Not enough bytes for FSBE record data + blip file name\n");
                } else {
                    struct OfficeArtRecordHeader_Unpacked embeddedBlip_rh;
                    const unsigned char *embeddedBlip;
                    size_t embeddedBlip_size;
                    char *blip_file_name       = NULL;
                    char blip_name_buffer[256] = {0};

                    if (FBSE_record_data->cbName > 0) {
                        memcpy(blip_name_buffer,
                               (char *)(index +
                                        sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) +
                                        sizeof(struct OfficeArtFBSE_PackedLittleEndian)),
                               (size_t)FBSE_record_data->cbName);
                        blip_name_buffer[FBSE_record_data->cbName] = '\0';

                        blip_file_name = blip_name_buffer;
                        cli_dbgmsg("Blip file name: %s\n", blip_file_name);
                    }

                    embeddedBlip = (const unsigned char *)(index +
                                                           sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) +
                                                           sizeof(struct OfficeArtFBSE_PackedLittleEndian) +
                                                           (size_t)FBSE_record_data->cbName);

                    embeddedBlip_size = remaining -
                                        sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) -
                                        sizeof(struct OfficeArtFBSE_PackedLittleEndian) -
                                        (size_t)FBSE_record_data->cbName;

                    if (le32_to_host(FBSE_record_data->size) > embeddedBlip_size) {
                        cli_dbgmsg("process_blip_store_container: WARNING: The File Blip Store Entry claims that the Blip data is bigger than the remaining bytes in the record!\n");
                        cli_dbgmsg("process_blip_store_container:   %d > %zu!\n", le32_to_host(FBSE_record_data->size), embeddedBlip_size);
                    } else {
                        /* limit embeddedBlip_size to the size of what's actually left */
                        embeddedBlip_size = le32_to_host(FBSE_record_data->size);
                    }

                    if (CL_SUCCESS != read_office_art_record_header(embeddedBlip, embeddedBlip_size, &embeddedBlip_rh)) {
                        /* Failed to get header, abort. */
                        cli_dbgmsg("process_blip_store_container: Failed to get header\n");
                        goto done;
                    }
                    status = process_blip_record(&embeddedBlip_rh, embeddedBlip, embeddedBlip_size, ctx);
                    if (CL_SUCCESS != status) {
                        goto done;
                    }
                }
            }

        } else if ((0xF018 <= rh.recType) && (0xF117 >= rh.recType)) {
            /* it's an OfficeArtBlip record */
            cli_dbgmsg("process_blip_store_container: Found a Blip record\n");
            status = process_blip_record(&rh, index, remaining, ctx);
            if (CL_SUCCESS != status) {
                goto done;
            }

        } else {
            /* unexpected record type. */
            cli_dbgmsg("process_blip_store_container: Unexpected record type\n");
        }

        if (remaining < sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) + rh.recLen) {
            remaining = 0;
        } else {
            remaining -= sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) + rh.recLen;
            index += sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) + rh.recLen;
        }
    }

    status = CL_SUCCESS;

done:

    return status;
}

cl_error_t cli_extract_images_from_drawing_group(const unsigned char *drawinggroup, size_t drawinggroup_len, cli_ctx *ctx)
{
    cl_error_t status = CL_EARG;

    struct OfficeArtRecordHeader_Unpacked rh;
    const unsigned char *index = drawinggroup;
    size_t remaining           = drawinggroup_len;

    if (NULL == drawinggroup || 0 == drawinggroup_len) {
        cli_dbgmsg("cli_extract_images_from_drawing_group: Invalid arguments\n");
        goto done;
    }

    if (CL_SUCCESS != read_office_art_record_header(drawinggroup, drawinggroup_len, &rh)) {
        /* Failed to get header, abort. */
        cli_dbgmsg("cli_extract_images_from_drawing_group: Failed to get drawing group record header\n");
        goto done;
    }

    if (!((0xF == rh.recVer) &&
          (0x000 == rh.recInstance) &&
          (0xF000 == rh.recType))) {
        /* Invalid record values for drawing group record header */
        cli_dbgmsg("cli_extract_images_from_drawing_group: Invalid record values for drawing group record header\n");
        goto done;
    }

    if (rh.recLen > drawinggroup_len) {
        /* Record header claims to be longer than our drawing group buffer */
        cli_dbgmsg("cli_extract_images_from_drawing_group: Record header claims to be longer than our drawing group buffer:\n");
        cli_dbgmsg("cli_extract_images_from_drawing_group:   %u > %zu\n", rh.recLen, drawinggroup_len);
    }

    /* Looks like we really found an Office Art Drawing Group (container).
     * See section 2.2.12 OfficeArtDggContainer in:
     * https://interoperability.blob.core.windows.net/files/MS-ODRAW/%5bMS-ODRAW%5d.pdf */
    cli_dbgmsg("cli_extract_images_from_drawing_group: Found drawing group of size %u bytes\n", rh.recLen);

    /* Just skip over this first header */
    if (remaining < sizeof(struct OfficeArtRecordHeader_PackedLittleEndian)) {
        remaining = 0;
    } else {
        remaining -= sizeof(struct OfficeArtRecordHeader_PackedLittleEndian);
        index += sizeof(struct OfficeArtRecordHeader_PackedLittleEndian);
    }

    while (0 < remaining) {
        if (CL_SUCCESS != read_office_art_record_header(index, remaining, &rh)) {
            /* Failed to get header, abort. */
            cli_dbgmsg("cli_extract_images_from_drawing_group: Failed to get header\n");
            goto done;
        }

        if (sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) > remaining) {
            cli_dbgmsg("cli_extract_images_from_drawing_group: Not enough data remaining for BLIP store.\n");
            goto done;
        }

        if ((0xF == rh.recVer) &&
            (0xF001 == rh.recType)) {
            /* Looks like we found a BLIP store container (array of OfficeArtBStoreContainerFileBlock records)
             * See section 2.2.20 OfficeArtBStoreContainer in:
             * https://interoperability.blob.core.windows.net/files/MS-ODRAW/%5bMS-ODRAW%5d.pdf */
            const unsigned char *start_of_blip_store_container = index + sizeof(struct OfficeArtRecordHeader_PackedLittleEndian);
            size_t blip_store_container_len                    = remaining - sizeof(struct OfficeArtRecordHeader_PackedLittleEndian);

            cli_dbgmsg("cli_extract_images_from_drawing_group: Found an OfficeArtBStoreContainerFileBlock (Blip store).\n");
            cli_dbgmsg("cli_extract_images_from_drawing_group:   size: %u bytes, contains: %u file block records\n",
                       rh.recLen, rh.recInstance);

            if (rh.recLen > blip_store_container_len) {
                cli_dbgmsg("cli_extract_images_from_drawing_group: WARNING: The blip store header claims to be bigger than the remaining bytes in the drawing group!\n");
                cli_dbgmsg("cli_extract_images_from_drawing_group:   %d > %zu!\n", rh.recLen, blip_store_container_len);
            } else {
                /* limit rgfb enumeration to the size of the blip store */
                blip_store_container_len = rh.recLen;
            }

            status = process_blip_store_container(start_of_blip_store_container, blip_store_container_len, ctx);
            if (CL_SUCCESS != status) {
                goto done;
            }
        }

        if (remaining < sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) + rh.recLen) {
            remaining = 0;
        } else {
            remaining -= sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) + rh.recLen;
            index += sizeof(struct OfficeArtRecordHeader_PackedLittleEndian) + rh.recLen;
        }
    }

    status = CL_SUCCESS;

done:

    return status;
}

cl_error_t cli_extract_xlm_macros_and_images(const char *dir, cli_ctx *ctx, char *hash, uint32_t which)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;
    char fullname[PATH_MAX];
    int in_fd = -1, out_fd = -1;
    FILE *out_file = NULL;
    const char *opcode_name;
    char *tempfile = NULL;
    char *data     = NULL;
    int len;
    size_t size_written;
    size_t size_read;
    struct {
        uint16_t opcode;
        uint16_t length;
    } __attribute__((packed)) biff_header;
    const char FILE_HEADER[] = "-- BIFF content extracted and disassembled from CL_TYPE_MSXL .xls file because a XLM macro was found in the document\n";

    unsigned char *drawinggroup = NULL;
    size_t drawinggroup_len     = 0;

    biff8_opcode previous_biff8_opcode = 0x0; // Initialize to 0x0, which isn't even in our enum.
                                              // This variable will allow the OPC_CONTINUE record
                                              // to know which record it is continuing.

    snprintf(fullname, sizeof(fullname), "%s" PATHSEP "%s_%u", dir, hash, which);
    fullname[sizeof(fullname) - 1] = '\0';
    in_fd                          = open(fullname, O_RDONLY | O_BINARY);

    if (in_fd == -1) {
        cli_dbgmsg("[cli_extract_xlm_macros_and_images] Failed to open input file\n");
        /* Don't return an error. If the file is missing, an error probably occurred
         * earlier, such as a UTF8 conversion error in parse_formula() and so the file was never written.
         * There are no macros to scan, so report SUCCESS / CLEAN. */
        goto done;
    }

    if ((ret = cli_gentempfd_with_prefix(ctx->this_layer_tmpdir, "xlm_macros", &tempfile, &out_fd)) != CL_SUCCESS) {
        cli_dbgmsg("[cli_extract_xlm_macros_and_images] Failed to open output file descriptor\n");
        status = ret;
        goto done;
    }

    out_file = fdopen(out_fd, "wb");
    if (NULL == out_file) {
        cli_dbgmsg("[cli_extract_xlm_macros_and_images] Failed to open output file pointer\n");
        goto done;
    }

    if ((data = malloc(BIFF8_MAX_RECORD_LENGTH)) == NULL) {
        cli_dbgmsg("[cli_extract_xlm_macros_and_images] Failed to allocate memory for BIFF data\n");
        status = CL_EMEM;
        goto done;
    }

    if (cli_writen(out_fd, FILE_HEADER, sizeof(FILE_HEADER) - 1) != sizeof(FILE_HEADER) - 1) {
        cli_dbgmsg("[cli_extract_xlm_macros_and_images] Failed to write header\n");
        status = CL_EWRITE;
        goto done;
    }

    cli_dbgmsg("[cli_extract_xlm_macros_and_images] Extracting macros to %s\n", tempfile);

    while (sizeof(biff_header) == (size_read = cli_readn(in_fd, &biff_header, sizeof(biff_header)))) {
        biff_header.opcode = le16_to_host(biff_header.opcode);
        biff_header.length = le16_to_host(biff_header.length);

        if (biff_header.opcode < sizeof(OPCODE_NAMES) / sizeof(OPCODE_NAMES[0])) {
            opcode_name = OPCODE_NAMES[biff_header.opcode];
        } else {
            opcode_name = NULL;
        }

        len = fprintf(out_file, "%04x %6d   %s", biff_header.opcode, biff_header.length, opcode_name == NULL ? "<unknown>" : opcode_name);
        if (len < 0) {
            cli_dbgmsg("[cli_extract_xlm_macros_and_images] Error formatting opcode message\n");
            status = CL_EFORMAT;
            goto done;
        }
        len = 0;

        if (biff_header.length > BIFF8_MAX_RECORD_LENGTH) {
            cli_dbgmsg("[cli_extract_xlm_macros_and_images] Record size exceeds maximum allowed\n");
            status = CL_EFORMAT;
            goto done;
        }

        if (cli_readn(in_fd, data, biff_header.length) != biff_header.length) {
            cli_dbgmsg("[cli_extract_xlm_macros_and_images] Failed to read BIFF record data\n");
            status = CL_EREAD;
            goto done;
        }

        switch (biff_header.opcode) {
            case OPC_FORMULA: {
                struct {
                    uint16_t row;
                    uint16_t column;
                    uint16_t length;
                } formula_header;

                if (biff_header.length >= 21) {
                    formula_header.row    = data[0] | (data[1] << 8);
                    formula_header.column = data[2] | (data[3] << 8);
                    formula_header.length = data[20] | (data[21] << 8);

                    len = fprintf(
                        out_file,
                        " - R%dC%d len=%d ",
                        (unsigned)(formula_header.row + 1),
                        (unsigned)(formula_header.column + 1),
                        formula_header.length);
                    if (len < 0) {
                        cli_dbgmsg("[cli_extract_xlm_macros_and_images] Error formatting FORMULA record message\n");

                        // Move along to the next record.
                        break;
                    }

                    ret = parse_formula(out_file, &data[22], biff_header.length - 21);
                    if (CL_SUCCESS != ret) {
                        cli_dbgmsg("[cli_extract_xlm_macros_and_images] Error parsing formula in FORMULA record message\n");

                        // Move along to the next record.
                        break;
                    }

                    // formula successfully parsed.
                }

                break;
            }
            case OPC_NAME: {
                if (biff_header.length >= 16) {
                    if (data[0] & 0x20) {
                        char code = data[14] != 0 ? data[14] : data[15];
                        char *name;
                        switch (code) {
                            case 1:
                                name = "auto_open";
                                break;
                            case 2:
                                name = "auto_close";
                                break;
                            default:
                                name = "?";
                                break;
                        }

                        len = fprintf(out_file, " - built-in-name %u %s", (unsigned)code, name);
                    } else {
                        int name_len  = data[3] | (data[4] << 8);
                        size_t offset = data[14] != 0 ? 14 : 15;
                        name_len      = min(name_len, (int)(biff_header.length - offset));

                        len = fprintf(out_file, " - %.*s", name_len, &data[offset]);
                    }
                    if (len < 0) {
                        cli_dbgmsg("[cli_extract_xlm_macros_and_images] Error formatting NAME record message\n");

                        // Move along to the next record.
                        break;
                    }

                    // name record successfully parsed
                } else {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images] Skipping broken NAME record (length %u)\n", biff_header.length);
                }

                break;
            }
            case OPC_MSODRAWINGGROUP: {
                /*
                 * Extract the entire drawing group before we parse it.
                 */
                if (NULL == drawinggroup) {
                    /* Found beginning of a drawing group */
                    drawinggroup_len = (size_t)biff_header.length;
                    drawinggroup     = malloc(drawinggroup_len);
                    memcpy(drawinggroup, data, drawinggroup_len);
                    // cli_dbgmsg("Collected %zu drawing group bytes\n", drawinggroup_len);

                } else {
                    /* already found the beginning of a drawing group, extract the remaining chunks */
                    drawinggroup_len += biff_header.length;
                    CLI_MAX_REALLOC_OR_GOTO_DONE(drawinggroup, drawinggroup_len, status = CL_EMEM);
                    memcpy(drawinggroup + (drawinggroup_len - biff_header.length), data, biff_header.length);
                    // cli_dbgmsg("Collected %d drawing group bytes\n", biff_header.length);
                }
                break;
            }
            case OPC_CONTINUE: {
                if ((OPC_MSODRAWINGGROUP == previous_biff8_opcode) &&
                    (NULL != drawinggroup)) {
                    /* already found the beginning of an image, extract the remaining chunks */
                    drawinggroup_len += biff_header.length;
                    CLI_MAX_REALLOC_OR_GOTO_DONE(drawinggroup, drawinggroup_len, status = CL_EMEM);
                    memcpy(drawinggroup + (drawinggroup_len - biff_header.length), data, biff_header.length);
                    // cli_dbgmsg("Collected %d image bytes\n", biff_header.length);
                }
                break;
            }
            case OPC_BOUNDSHEET: {
                if (biff_header.length >= 6) {
                    const char *sheet_type;
                    const char *sheet_state;

                    switch (data[4]) {
                        case 0:
                            sheet_state = "visible";
                            break;
                        case 1:
                            sheet_state = "hidden";
                            break;
                        case 2:
                            sheet_state = "very hidden";
                            break;
                        default:
                            sheet_state = "unknown visibility";
                            break;
                    }
                    switch (data[5]) {
                        case 0:
                            sheet_type = "worksheet or dialog sheet";
                            break;
                        case 1:
                            sheet_type = "Excel 4.0 macro sheet";
                            break;
                        case 2:
                            sheet_type = "chart";
                            break;
                        case 6:
                            sheet_type = "Visual Basic module";
                            break;
                        default:
                            sheet_type = "unknown type";
                            break;
                    }

                    len = fprintf(out_file, " - %s, %s", sheet_type, sheet_state);
                    if (len < 0) {
                        cli_dbgmsg("[cli_extract_xlm_macros_and_images] Error formatting BOUNDSHEET record message\n");
                        // Move along to the next record.
                        break;
                    }

                    // boundsheet record successfully parsed
                } else {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images] Skipping broken BOUNDSHEET record (length %u)\n", biff_header.length);
                }
                break;
            }
            case OPC_STRING: {
                // Documented in Microsoft Office Excel97-2007Binary File Format (.xls) Specification
                // Page 17: Unicode Strings in BIFF8
                if (biff_header.length >= 4) {
                    uint16_t string_length = data[0] | (data[1] << 8);
                    uint8_t flags          = data[2];

                    if (flags & 0x4) {
                        cli_dbgmsg("[cli_extract_xlm_macros_and_images] East Asian extended strings not implemented\n");
                    }

                    if (flags & 0x8) {
                        cli_dbgmsg("[cli_extract_xlm_macros_and_images] Rich strings not implemented\n");
                    }

                    if (!(flags & 0x1)) {
                        // String is compressed
                        len = fprintf(out_file, " - \"%.*s\"", (int)(biff_header.length - 3), &data[6]);
                        if (len < 0) {
                            cli_dbgmsg("[cli_extract_xlm_macros_and_images] Error formatting STRING record message with ANSI content\n");

                            // Move along to the next record.
                            break;
                        }
                    } else {
                        char *utf8       = NULL;
                        size_t utf8_size = 0;

                        len = fprintf(out_file, " - ");
                        if (len < 0) {
                            cli_dbgmsg("[cli_extract_xlm_macros_and_images] Error formatting STRING record message with UTF16 content\n");

                            // Move along to the next record.
                            break;
                        }

                        if (string_length > biff_header.length - 3) {
                            string_length = biff_header.length - 3;
                        }

                        if (CL_SUCCESS == cli_codepage_to_utf8(&data[3], string_length, CODEPAGE_UTF16_LE, &utf8, &utf8_size)) {
                            if (0 < utf8_size) {
                                size_written = fwrite(utf8, 1, utf8_size, out_file);
                                free(utf8);
                                if (size_written < utf8_size) {
                                    cli_dbgmsg("[cli_extract_xlm_macros_and_images] Error writing STRING record message with UTF16LE content\n");
                                    goto done;
                                }
                            }
                        } else {
                            cli_dbgmsg("[cli_extract_xlm_macros_and_images] Failed to decode UTF16LE string\n");
                            len = fprintf(out_file, "<Failed to decode UTF16LE string>");
                            if (len < 0) {
                                cli_dbgmsg("[cli_extract_xlm_macros_and_images] Error formatting STRING record message with UTF16LE content\n");
                                goto done;
                            }
                        }
                    }
                } else {
                    cli_dbgmsg("[cli_extract_xlm_macros_and_images] Skipping broken STRING record (length %u)\n", biff_header.length);

                    // Move along to the next record.
                    break;
                }

                // Not implemented. See Microsoft Office Excel97-2007Binary File Format (.xls) Specification Page 18 for details.
                break;
            }
            default: {
                break;
            }
        }

        len = fputc('\n', out_file);
        if (len == EOF) {
            cli_dbgmsg("[cli_extract_xlm_macros_and_images] Error writing new line to out file\n");
            goto done;
        }

        /* Keep track of which biff record we're continuing if we encounter OPC_CONTINUE */
        if (OPC_CONTINUE != biff_header.opcode) {
            previous_biff8_opcode = biff_header.opcode;
        }
    }

    /* Scan the extracted content */
    if (lseek(out_fd, 0, SEEK_SET) != 0) {
        cli_dbgmsg("cli_extract_xlm_macros_and_images: Failed to seek to beginning of temporary file\n");
        status = CL_ESEEK;
        goto done;
    }

    if (CL_VIRUS == cli_scan_desc(out_fd, ctx, CL_TYPE_SCRIPT, false, NULL, AC_SCAN_VIR,
                                  NULL, "xlm-macro", tempfile, LAYER_ATTRIBUTES_NONE)) {
        status = CL_VIRUS;
        goto done;
    }

    /* If a read failed, return with an error. */
    if (size_read == (size_t)-1) {
        cli_dbgmsg("cli_extract_xlm_macros_and_images: Read error occurred when trying to read BIFF header. Truncated or malformed XLM macro file?\n");
        status = CL_EREAD;
        goto done;
    }

    if (NULL != drawinggroup) {
        /*
         * A drawing group was extracted, now we need to find all the images inside.
         * If we fail to extract images, that's fine.
         */
        ret = cli_extract_images_from_drawing_group(drawinggroup, drawinggroup_len, ctx);
        if (CL_SUCCESS != ret) {
            status = ret;
            goto done;
        }
    }

    status = CL_SUCCESS;

done:
    CLI_FREE_AND_SET_NULL(drawinggroup);

    if (in_fd != -1) {
        close(in_fd);
        in_fd = -1;
    }

    if (NULL != out_file) {
        fclose(out_file);
        out_file = NULL;
    } else if (-1 != out_fd) {
        close(out_fd);
        out_fd = -1;
    }

    CLI_FREE_AND_SET_NULL(data);

    if (tempfile && !ctx->engine->keeptmp) {
        remove(tempfile);
    }
    CLI_FREE_AND_SET_NULL(tempfile);

    return status;
}
