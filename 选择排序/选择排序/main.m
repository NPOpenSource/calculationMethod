//
//  main.m
//  选择排序
//
//  Created by 温杰 on 2018/4/18.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import <Foundation/Foundation.h>

int* getDataWithLength(int length){
    int * a = malloc(length*4);
    for (int i =0; i<length;i++){
        a[i]=arc4random()%10000;
    }
    return a;
}


void printData(int * data,int length){
    for (int i =0; i<length;i++){
        NSLog(@"%d",data[i]);
    }
}

void exch(int * a ,int x,int y){
    int change =a[x];
    a[x]=a[y];
    a[y]=change;
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        int length = 1000;
     int* data =  getDataWithLength(length);
        printData(data, length);
        for (int i =0; i<length; i++) {
            int min = i;
            for (int j=i+1; j<length; j++) {
                if (data[min]>data[j]) {
                    min = j;
                }
            }
            exch(data, min, i);
        }
        free(data);
        printData(data, length);
    }
    
    return 0;
}
