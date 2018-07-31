//
//  main.m
//  算法导论
//
//  Created by 温杰 on 2018/5/9.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Util.h"
#import "InsertionSort.h"
#import "SelectionSort.h"
#import "Merge.h"
#import "BinarySearch.h"
#import "Bubblesort.h"
#import "Heapify.h"
#import "Tree.h"
#import "RedAndBlackTree.h"
#import "RBCTree.h"
#import "RDTree.h"
void ChapterTowo(void){
    NSLog(@"第二章");
    //插入排序
    int length = 5;
    int * A = getMallocRandomNum(length, 1000);
     printArr(A, length);

//    bubbleSort(A, length);
    int num = 0;
   int a[5] = {2,3,2,1,6};
    mergeSortReverseOrderPair(a, 0, 4, &num);
    NSLog(@"%d",num);
//    printArr(A, length);
    
    //    mergeSort(A, 0, length-1);
//    [InsertionSort insertionSortBinarySearch:A length:length];
    //    [InsertionSort insertionSort:A length:length];
    //    [InsertionSort insertionSortAscendingOrder:A length:length];
    //    [SelectionSort selectionSort:A length:length];
    //    [InsertionSort insertionRecursionSort:A length:length];
    //   binarySearchEqualSortArr(A, 0, length-1, 11);
    
    //    int B[7]={1,2,3,5,2,4,6};
    //    merge(B, 1, 3, 4);
}

void chapterSix(){
    NSLog(@"第六章");
    int length = 10;
    int * A = getMallocRandomNum(length, 1000);
    printArr(A, length);
    heapSort(A, length);
    printArr(A, length);
    
    
    Heapify * heap = [Heapify new];
    [heap maxHeapInsert:10];
    [heap print];
    [heap maxHeapInsert:11];
    [heap print];
    [heap maxHeapInsert:9];
    [heap print];
    [heap heapExtractMax];
    [heap print];
    [heap maxHeapInsert:14];
    [heap print];
    [heap maxHeapInsert:18];
    [heap print];
    [heap heapExtractMax];
    [heap print];
    [heap heapExtractMax];
    [heap print];
}

void chapterSeven(){
    NSLog(@"第七章");
    int length = 10;
    int * A = getMallocRandomNum(length, 1000);
    printArr(A, length);
    cquickSort(A,0 ,9);
    printArr(A, length);
    A = getMallocRandomNum(length, 1000);
    printArr(A, length);
    randomizedQuickSort(A,0 ,9);
    printArr(A, length);
}

void chapterEight(void){
    NSLog(@"第八章");
    int length = 100;
    int * A = getMallocRandomNum(length, 10);
    int * B = getMallocSize(length);
    printArr(A, length);
    countingSort(A,B,10 , length);
    printArr(B, length);

    A = getMallocRandomNum(length, 1000);
   printArr(A, length);
    radixSort(A, 4, length);
   printArr(A, length);
    NSLog(@"基于计数排序");
//    length= 10;
   int* M = getMallocRandomNum(length, 1000);
    printArr(M, length);
    radixSortBasecountingSort(M, 4, length);
    printArr(M, length);
    
    
    
}

void chapterElevent(){
    NSLog(@"第十二章");
    Tree * tree = [Tree new];
    [tree ttreeInsert:15];
   
     [tree ttreeInsert:13];
      [tree ttreeInsert:9];
    [tree ttreeInsert:2];
    [tree ttreeInsert:3];
    [tree ttreeInsert:4];
    [tree ttreeInsert:6];
    [tree ttreeInsert:7];
    [tree ttreeInsert:17];
    [tree ttreeInsert:18];
    [tree ttreeInsert:20];
    [tree ttreeInsert:5];
    NSLog(@"中序排列");
    [tree middleOrderTreeWalk:tree.ttroot.root];
    NSLog(@"前序排列");
    [tree middleOrderTreeWalk:tree.ttroot.root];
    
    TTree * x = [tree searchKey:17 rootTree:tree.ttroot.root];
    NSLog(@"查找17 %d",x.key);
    x=[tree ttreeMinimum:tree.ttroot.root];
    NSLog(@"最小值 %d",x.key);
    x=[tree ttreeMaximum:tree.ttroot.root];
    NSLog(@"最大值 %d",x.key);
     x = [tree searchKey:17 rootTree:tree.ttroot.root];
    x = [tree treePredecessOr:x];
    NSLog(@"17 前趋 %d",x.key);
    x = [tree searchKey:17 rootTree:tree.ttroot.root];
//    x = [tree treeSuccessOr:x];
    NSLog(@"17 后继 %d",x.key);
    [tree leftRoTate:x];
//   x = [tree delete:13];
//    NSLog(@"6 删除 %d",x.key);
      x = [tree treeSuccessOr:x];

    [tree rightRotate:x];
    
    [tree middleOrderTreeWalk:tree.ttroot.root];


    
  
}
void chapter13(){
    NSLog(@"第十三章");
    RDTree * tree = [RDTree new];
    NSArray * array = @[@11,@7,@1,@2,@8,@14,@15,@5,@4];
    for (NSNumber * number in array) {
        [tree ttreeInsert:number.intValue];
    }
//    [tree middleOrderTreeWalk:tree.ttroot.root];
    [tree delete:8];
     NSLog(@"删除");
    [tree middleOrderTreeWalk:tree.ttroot.root];
    
    NSLog(@"算法导论写法");
    RedAndBlackTree * redBlockTree = [RedAndBlackTree new];
    for (NSNumber * number in array) {
        [redBlockTree treeInsert:number.intValue];
    }
//    [redBlockTree inorderTreeWalk];
    [redBlockTree rb_delete:8];
    NSLog(@"删除");
    [redBlockTree inorderTreeWalk];

    return;
    [redBlockTree rb_delete:8];
    [redBlockTree rb_delete:14];
    [redBlockTree rb_delete:7];
    [redBlockTree rb_delete:11];
    [redBlockTree inorderTreeWalk];

    
//    redBlockTree = [RedAndBlackTree new];
//    [redBlockTree RB_treeInsert:11];
//    [redBlockTree RB_treeInsert:7];
//    [redBlockTree RB_treeInsert:1];
//    [redBlockTree RB_treeInsert:2];
//    [redBlockTree RB_treeInsert:8];
//    [redBlockTree RB_treeInsert:14];
//    [redBlockTree RB_treeInsert:15];
//    [redBlockTree RB_treeInsert:5];
//    [redBlockTree RB_treeInsert:4];
//    [redBlockTree inorderTreeWalk];
//    [redBlockTree rb_delete:15];
//    [redBlockTree rb_delete:8];
//    [redBlockTree inorderTreeWalk];

}

int main(int argc, const char * argv[]) {


//    ChapterTowo();
//    chapterSix();
//    chapterSeven();
//    chapterEight();
//    chapterElevent();
//    chapter13();
    NSString * str = @"刘宏哲、李明、赵迎新、许兆光、张婷、杨彬、王猛、王洁、高志伟、赵杰、王洪枝、丁江庆、丁敬恩、李伟、周余钱、伊宝德、霍浩庆、裴明晓、刘信恒、叶东、李晓洁、滕柳、彭周强、刘天赐、赵文民、刘龙飞、王蕾、刘孝宝、栗翠霄、王双、王毅、陈维锋、刘冬、宋明光、贾海亮、杨凯、廖智勇、温杰、李晓声、陈永昊、张丽敏、卢晓海、郭晨、王海名、姚晓峰、孙丽真、康宁、张裕洲、张宏峰、张鹏霄、王艺菲、杨志强、刘天赐、赵禹豪、宋子文、李佳林、刘春梅、李繁荣、吴本立、张冬、范素刚、周从强、鄂宏伟、田倩倩、张占鹤、谭志强、姜龙、刘亚南、杨坤林、李永慧、朱良杰、夏泉峰、霍浩庆、裴明晓、刘信恒、李晓洁、滕柳、林瑞凯、刘宏哲、李明、赵迎新、许兆光、张婷、杨彬、王猛、王洁、高志伟、赵杰、王洪枝、丁江庆、丁敬恩、李伟、周余钱、彭周强、刘宏哲、李明、赵迎新、许兆光、张婷、杨彬、王猛、王洁、高志伟、丁江庆、丁敬恩、李伟、周余钱";
    NSArray * array  = [str componentsSeparatedByString:@"、"];
    NSMutableSet * set=  [NSMutableSet new];
    for (NSString *name in array) {
        [set addObject:name];
    }
    str = @"";
    for (NSString * name in set) {
        str = [str stringByAppendingString:name];
      str =  [str stringByAppendingString:@"、"];
    }
    NSLog(@"%d",set.count);
    NSLog(@"%@",str);
    
    return 0;
}
